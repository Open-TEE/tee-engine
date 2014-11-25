/*****************************************************************************
** Copyright (C) 2014 Intel Corporation.                                    **
**                                                                          **
** Licensed under the Apache License, Version 2.0 (the "License");          **
** you may not use this file except in compliance with the License.         **
** You may obtain a copy of the License at                                  **
**                                                                          **
**      http://www.apache.org/licenses/LICENSE-2.0                          **
**                                                                          **
** Unless required by applicable law or agreed to in writing, software      **
** distributed under the License is distributed on an "AS IS" BASIS,        **
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. **
** See the License for the specific language governing permissions and      **
** limitations under the License.                                           **
*****************************************************************************/

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "com_protocol.h"
#include "dynamic_loader.h"
#include "ta_exit_states.h"
#include "ta_extern_resources.h"
#include "ta_internal_thread.h"
#include "tee_data_types.h"
#include "ta_io_thread.h"
#include "tee_list.h"
#include "tee_logging.h"

/* The client names for the params */
#define TEEC_NONE			0x00000000
#define TEEC_VALUE_INPUT		0x00000001
#define TEEC_VALUE_OUTPUT		0x00000002
#define TEEC_VALUE_INOUT		0x00000003
#define TEEC_MEMREF_TEMP_INPUT		0x00000005
#define TEEC_MEMREF_TEMP_OUTPUT		0x00000006
#define TEEC_MEMREF_TEMP_INOUT		0x00000007
#define TEEC_MEMREF_WHOLE		0x0000000C
#define TEEC_MEMREF_PARTIAL_INPUT	0x0000000D
#define TEEC_MEMREF_PARTIAL_OUTPUT	0x0000000E
#define TEEC_MEMREF_PARTIAL_INOUT	0x0000000F

#define SESSION_STATE_ACTIVE		0x000000F0

struct __TEE_TASessionHandle {
	uint64_t sess_id;
	uint8_t session_state;
};

static void add_msg_done_queue_and_notify(struct ta_task *out_task)
{
	const uint64_t event = 1;

	/* Lock task queue from logic thread */
	if (pthread_mutex_lock(&done_list_mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock the mutex: %s", strerror(errno))
		return;
	}

	/* enqueue the task manager queue */
	list_add_before(&out_task->list, &tasks_done.list);

	if (pthread_mutex_unlock(&done_list_mutex)) {
		/* For now, just log error */
		OT_LOG(LOG_ERR, "Failed to lock the mutex: %s", strerror(errno))
		return;
	}

	/* notify the I/O thread that there is something at output queue */
	if (write(event_fd, &event, sizeof(uint64_t)) == -1) {
		OT_LOG(LOG_ERR, "Failed to notify the io thread: %s", strerror(errno))
		/* TODO: See what is causing it! */
	}
}

static bool wait_response_msg()
{
	if (pthread_mutex_lock(&block_internal_thread_mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock the mutex");
		return false;
	}

	while (!response_msg) {
		if (pthread_cond_wait(&block_condition, &block_internal_thread_mutex)) {
			OT_LOG(LOG_ERR, "Failed to wait for condition");
			continue;
		}
	}

	if (pthread_mutex_unlock(&block_internal_thread_mutex))
		OT_LOG(LOG_ERR, "Failed to unlock the mutex");

	return true;
}

static bool get_vals_from_err_msg(void *msg, TEE_Result *ret_code, uint32_t *msg_origin)
{
	uint8_t msg_name;

	if (com_get_msg_name(msg, &msg_name)) {
		OT_LOG(LOG_ERR, "Failed to read msg name")
		return false;
	}

	if (msg_name != COM_MSG_NAME_ERROR)
		return false;

	if (msg_origin)
		*msg_origin = ((struct com_msg_error *)msg)->ret_origin;
	*ret_code = ((struct com_msg_error *)msg)->ret;

	return true;
}

static TEE_Result wait_and_handle_open_sess_resp(uint32_t paramTypes, TEE_Param params[4],
						 TEE_TASessionHandle *session,
						 uint32_t *returnOrigin)
{
	struct com_msg_open_session *resp_open_msg = NULL;
	TEE_Result ret;

	paramTypes = paramTypes;
	params = params;

	if (!wait_response_msg())
		goto err_com;

	resp_open_msg = response_msg;

	if (resp_open_msg->msg_hdr.msg_name != COM_MSG_NAME_OPEN_SESSION) {

		if (!get_vals_from_err_msg(response_msg, &ret, returnOrigin)) {
			OT_LOG(LOG_ERR, "Received unknown message")
			goto err_com;
		}

		goto err_msg;
	}

	/* TODO: Copy parameters */

	if (returnOrigin)
		*returnOrigin = resp_open_msg->return_origin;
	ret = resp_open_msg->return_code_open_session;
	if (ret != TEE_SUCCESS)
		goto err_ret;

	(*session)->sess_id = resp_open_msg->msg_hdr.sess_id;
	(*session)->session_state = SESSION_STATE_ACTIVE;

	free(resp_open_msg);

	return ret;

err_com:
	if (returnOrigin)
		*returnOrigin = TEE_ORIGIN_COMMS;
	ret = TEEC_ERROR_COMMUNICATION;

err_ret:
err_msg:
	free(resp_open_msg);
	free(*session);
	*session = NULL;
	return ret;
}

static int open_shared_mem(const char *name, void **buffer, int size, bool isOutput)
{
	int flag = 0;
	int fd;
	void *address = NULL;
	struct stat file_stat;

	if (!name || !buffer) {
		OT_LOG(LOG_ERR, "Invalid pointer");
		goto errorExit;
	}

	if (isOutput)
		flag |= O_RDONLY; /* It is an outbuffer only so we just need read access */
	else
		flag |= O_RDWR;

	fd = shm_open(name, flag, 0);
	if (fd == -1) {
		OT_LOG(LOG_ERR, "Failed to open the shared memory area");
		goto errorExit;
	}

	if (fstat(fd, &file_stat) == -1) {
		OT_LOG(LOG_ERR, "Failed to stat the shared memory region");
		goto unlinkExit;
	}

	if (file_stat.st_size != size) {
		OT_LOG(LOG_ERR, "Size mis-match");
		goto unlinkExit;
	}

	/* mmap does not allow for the size to be zero, however the TEEC API allows it, so map a
	 * size of 1 byte, though it will probably be mapped to a page
	 */
	address = mmap(NULL, size != 0 ? size : 1,
		       ((flag == O_RDONLY) ? PROT_READ : (PROT_WRITE | PROT_READ)),
		       MAP_SHARED, fd, 0);
	if (address == MAP_FAILED) {
		OT_LOG(LOG_ERR, "Failed to mmap the area");
		goto unlinkExit;
	}

	/* We have finished with the file handle as it has been mapped so don't leak it */
	close(fd);

	*buffer = address;

	return 0;

unlinkExit:
	close(fd);
errorExit:
	return -1;
}

static void copy_params_to_com_msg_op(struct com_msg_operation *operation, TEE_Param *params,
				      int32_t tee_param_types)
{
	int i;

	for (i = 0; i < 4; i++) {
		if (TEE_PARAM_TYPE_GET(tee_param_types, i) == TEE_PARAM_TYPE_VALUE_OUTPUT ||
		    TEE_PARAM_TYPE_GET(tee_param_types, i) == TEE_PARAM_TYPE_VALUE_INOUT) {

			/* We only have to copy back the output values, because the memory
			 * types point to shared memory so they are updated directly in place.
			 */
			memcpy(&operation->params[i].value,
			       &params[i].value,
			       sizeof(params[i].value));

		} else if (TEE_PARAM_TYPE_GET(tee_param_types, i) == TEE_PARAM_TYPE_MEMREF_INPUT ||
			   TEE_PARAM_TYPE_GET(tee_param_types, i) == TEE_PARAM_TYPE_MEMREF_OUTPUT ||
			   TEE_PARAM_TYPE_GET(tee_param_types, i) == TEE_PARAM_TYPE_MEMREF_INOUT) {

			/* unmap the shared memory regions as they are no longer valid for the TA
			 */
			if (params[i].memref.buffer)
				munmap(params[i].memref.buffer, params[i].memref.size);
		}
	}
}

static int copy_com_msg_op_to_param(struct com_msg_operation *operation, TEE_Param *params,
				    uint32_t *tee_param_types)
{
	int i;
	int types[4] = {0};
	bool isOutput;
	uint32_t param_types = operation->paramTypes;
	int ret = 0;

	memset(params, 0, 4 * sizeof(TEE_Param));

	for (i = 0; i < 4; i++) {
		if (TEE_PARAM_TYPE_GET(param_types, i) == TEEC_NONE) {
			continue;
		} else if (TEE_PARAM_TYPE_GET(param_types, i) == TEEC_VALUE_INPUT ||
			   TEE_PARAM_TYPE_GET(param_types, i) == TEEC_VALUE_INOUT) {

			memcpy(&params[i].value,
			       &operation->params[i].value, sizeof(params[i].value));

		} else {

			/* determine if this is a readonly memory area */
			if (TEE_PARAM_TYPE_GET(param_types, i) == TEEC_MEMREF_TEMP_OUTPUT ||
			    TEE_PARAM_TYPE_GET(param_types, i) == TEEC_MEMREF_PARTIAL_OUTPUT) {
				isOutput = true;
			} else {
				isOutput = false;
			}

			/* if there is some failure opening the shared memory just
			 * fail graefully */
			if (open_shared_mem(operation->params[i].memref.shm_area,
					    &params[i].memref.buffer,
					    operation->params[i].memref.size,
					    isOutput) == -1) {
				ret = -1;
			}

			params[i].memref.size = operation->params[i].memref.size;
		}

		/* convert the TEEC types to the TEE internal types */
		if (TEE_PARAM_TYPE_GET(param_types, i) == TEEC_MEMREF_WHOLE ||
		    TEE_PARAM_TYPE_GET(param_types, i) == TEEC_MEMREF_PARTIAL_INOUT) {

			types[i] = TEE_PARAM_TYPE_MEMREF_INOUT;

		} else if (TEE_PARAM_TYPE_GET(param_types, i) == TEEC_MEMREF_PARTIAL_INPUT) {

			types[i] = TEE_PARAM_TYPE_MEMREF_INPUT;

		} else if (TEE_PARAM_TYPE_GET(param_types, i) == TEEC_MEMREF_PARTIAL_OUTPUT) {

			types[i] = TEE_PARAM_TYPE_MEMREF_OUTPUT;

		} else {

			types[i] = TEE_PARAM_TYPE_GET(param_types, i);
		}
	}

	*tee_param_types = TEE_PARAM_TYPES(types[0], types[1], types[2], types[3]);

	if (ret == -1) /* clean up all memory that has been mmaped because of the error */
		copy_params_to_com_msg_op(operation, params, *tee_param_types);

	return ret;
}

static void open_session(struct ta_task *in_task)
{
	struct com_msg_open_session *open_msg = in_task->msg;
	uint32_t paramTypes;
	TEE_Param params[4];

	if (open_msg->msg_hdr.msg_name != COM_MSG_NAME_OPEN_SESSION ||
	    open_msg->msg_hdr.msg_type != COM_TYPE_QUERY) {
		OT_LOG(LOG_ERR, "Invalid message, ignore");
		free_task(in_task);
		return;
	}

	/* convert the paramaters from the message into TA format params */
	if (copy_com_msg_op_to_param(&open_msg->operation, params, &paramTypes) == -1) {
		OT_LOG(LOG_ERR, "Failed to copy operation");
		open_msg->return_code_open_session = TEE_ERROR_NO_DATA;
		open_msg->return_origin = TEE_ORIGIN_TEE;
		goto out;
	}

	/* Do the task */
	open_msg->return_code_open_session = interface->open_session(paramTypes, params,
								     (void **)&open_msg->sess_ctx);
	open_msg->return_origin = TEE_ORIGIN_TRUSTED_APP;

	/* Copy the data back from the TA to the client */
	copy_params_to_com_msg_op(&open_msg->operation, params, paramTypes);

out:
	open_msg->msg_hdr.msg_type = COM_TYPE_RESPONSE;
	add_msg_done_queue_and_notify(in_task);
}

static void invoke_cmd(struct ta_task *in_task)
{
	struct com_msg_invoke_cmd *invoke_msg = in_task->msg;
	uint32_t paramTypes;
	TEE_Param params[4];

	if (invoke_msg->msg_hdr.msg_name != COM_MSG_NAME_INVOKE_CMD ||
	    invoke_msg->msg_hdr.msg_type != COM_TYPE_QUERY) {
		OT_LOG(LOG_ERR, "Invalid message, ignore");
		free_task(in_task);
		return;
	}

	/* convert the paramaters from the message into TA format params */
	if (copy_com_msg_op_to_param(&invoke_msg->operation, params, &paramTypes)) {
		OT_LOG(LOG_ERR, "Failed to copy operation");
		invoke_msg->return_code = TEE_ERROR_NO_DATA;
		invoke_msg->return_origin = TEE_ORIGIN_TEE;
		goto out;
	}

	/* Do the task */
	invoke_msg->return_code = interface->invoke_cmd((void *)invoke_msg->sess_ctx,
							invoke_msg->cmd_id, paramTypes, params);

	invoke_msg->return_origin = TEE_ORIGIN_TRUSTED_APP;

	/* Copy the data back from the TA to the client */
	copy_params_to_com_msg_op(&invoke_msg->operation, params, paramTypes);

out:
	invoke_msg->msg_hdr.msg_type = COM_TYPE_RESPONSE;
	add_msg_done_queue_and_notify(in_task);
}

static void close_session(struct ta_task *in_task)
{
	struct com_msg_close_session *close_msg = in_task->msg;

	if (close_msg->msg_hdr.msg_name != COM_MSG_NAME_CLOSE_SESSION ||
	    close_msg->msg_hdr.msg_type != COM_TYPE_QUERY) {
		OT_LOG(LOG_ERR, "Invalid message, ignore");
		goto ignore_msg;
	}

	interface->close_session((void *)close_msg->sess_ctx);

	if (close_msg->should_ta_destroy) {
		interface->destroy();
		exit(TA_EXIT_DESTROY_ENTRY_EXEC);
	}

ignore_msg:
	free_task(in_task);
}

static void first_open_session_msg(struct com_msg_open_session *open_msg)
{
	struct ta_task *open_ta_task = NULL;

	open_ta_task = calloc(1, sizeof(struct ta_task));
	if (!open_ta_task) {
		OT_LOG(LOG_ERR, "Out of memory");
		exit(TA_EXIT_FIRST_OPEN_SESS_FAILED);
	}

	open_ta_task->msg = open_msg;
	open_ta_task->msg_len = sizeof(struct com_msg_open_session);

	open_session(open_ta_task);
}

static int map_create_entry_exit_value(TEE_Result ret)
{
	switch (ret) {
	case TEE_ERROR_GENERIC:
		return 10;
	case TEE_ERROR_ACCESS_DENIED:
		return 11;
	case TEE_ERROR_CANCEL:
		return 12;
	case TEE_ERROR_ACCESS_CONFLICT:
		return 13;
	case TEE_ERROR_EXCESS_DATA:
		return 14;
	case TEE_ERROR_BAD_FORMAT:
		return 15;
	case TEE_ERROR_BAD_PARAMETERS:
		return 16;
	case TEE_ERROR_BAD_STATE:
		return 17;
	case TEE_ERROR_ITEM_NOT_FOUND:
		return 18;
	case TEE_ERROR_NOT_IMPLEMENTED:
		return 19;
	case TEE_ERROR_NOT_SUPPORTED:
		return 20;
	case TEE_ERROR_NO_DATA:
		return 21;
	case TEE_ERROR_OUT_OF_MEMORY:
		return 22;
	case TEE_ERROR_BUSY:
		return 23;
	case TEE_ERROR_COMMUNICATION:
		return 24;
	case TEE_ERROR_SECURITY:
		return 25;
	case TEE_ERROR_SHORT_BUFFER:
		return 26;
	case TEE_PENDING:
		return 27;
	case TEE_ERROR_TIMEOUT:
		return 28;
	case TEE_ERROR_OVERFLOW:
		return 29;
	case TEE_ERROR_TARGET_DEAD:
		return 30;
	case TEE_ERROR_STORAGE_NO_SPACE:
		return 31;
	case TEE_ERROR_MAC_INVALID:
		return 32;
	case TEE_ERROR_SIGNATURE_INVALID:
		return 33;
	case TEE_ERROR_TIME_NOT_SET:
		return 34;
	case TEE_ERROR_TIME_NEEDS_RESET:
		return 35;
	default:
		OT_LOG(LOG_ERR, "Unknown error value");
		break;
	}

	OT_LOG(LOG_ERR, "Unknown create entry point exit value");
	exit(TA_EXIT_PANICKED);
}

TEE_Result ta_open_ta_session(TEE_UUID *destination, uint32_t cancellationRequestTimeout,
				     uint32_t paramTypes, TEE_Param params[4],
				     TEE_TASessionHandle *session, uint32_t *returnOrigin)
{
	struct ta_task *new_ta_task = NULL;

	cancellationRequestTimeout = cancellationRequestTimeout;
	paramTypes = paramTypes;
	params = params;

	if (!destination || !session) {
		OT_LOG(LOG_ERR, "Destination or session NULL");
		if (returnOrigin)
			*returnOrigin = TEE_ORIGIN_TEE;
		return TEE_ERROR_GENERIC;
	}

	*session = calloc(1, sizeof(struct __TEE_TASessionHandle));
	if (!*session) {
		OT_LOG(LOG_ERR, "out of memory")
		goto err;
	}

	new_ta_task = calloc(1, sizeof(struct ta_task));
	if (!new_ta_task) {
		OT_LOG(LOG_ERR, "Out of memory");
		goto err;
	}

	new_ta_task->msg_len = sizeof(struct com_msg_open_session);
	new_ta_task->msg = calloc(1, new_ta_task->msg_len);
	if (!new_ta_task->msg) {
		OT_LOG(LOG_ERR, "Out of memory");
		goto err;
	}

	/* Message header */
	((struct com_msg_open_session *)new_ta_task->msg)->msg_hdr.msg_name = COM_MSG_NAME_OPEN_SESSION;
	((struct com_msg_open_session *)new_ta_task->msg)->msg_hdr.msg_type = COM_TYPE_QUERY;
	((struct com_msg_open_session *)new_ta_task->msg)->msg_hdr.sess_id = 0;

	/* TODO: Copy parameters */
	memcpy(&((struct com_msg_open_session *)new_ta_task->msg)->uuid,
	       destination, sizeof(TEE_UUID));

	add_msg_done_queue_and_notify(new_ta_task);

	return wait_and_handle_open_sess_resp(paramTypes, params, session, returnOrigin);

err:
	free(*session);
	*session = NULL;
	free(new_ta_task);
	if (returnOrigin)
		*returnOrigin = TEE_ORIGIN_TEE;
	return TEE_ERROR_GENERIC;
}

void ta_close_ta_session(TEE_TASessionHandle session)
{
	OT_LOG_STR("ta_close_ta_session")

	session = session;
}

TEE_Result ta_invoke_ta_command(TEE_TASessionHandle session,
				       uint32_t cancellationRequestTimeout,
				       uint32_t commandID, uint32_t paramTypes, TEE_Param params[4],
				       uint32_t *returnOrigin)
{
	OT_LOG_STR("ta_invoke_ta_command")

	commandID = commandID;
	cancellationRequestTimeout = cancellationRequestTimeout;
	paramTypes = paramTypes;
	params = params;
	session = session;
	returnOrigin = returnOrigin;

	return TEE_ERROR_NOT_IMPLEMENTED;
}

void *ta_internal_thread(void *arg)
{
	int ret;
	TEE_Result tee_ret;
	struct ta_task *task = NULL;
	uint8_t com_msg_name;

	tee_ret = interface->create();
	if (tee_ret != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TA create entry point failed");
		exit(map_create_entry_exit_value(tee_ret));
	}

	first_open_session_msg(arg);

	for (;;) {
		ret = pthread_mutex_lock(&todo_list_mutex);
		if (ret != 0) {
			OT_LOG(LOG_ERR, "Failed to lock the mutex");
			continue;
		}

		/* Wait for a task to become available */
		while (list_is_empty(&tasks_todo.list)) {
			ret = pthread_cond_wait(&condition, &todo_list_mutex);
			if (ret != 0) {
				OT_LOG(LOG_ERR, "Failed to wait for condition");
				continue;
			}
		}

		task = LIST_ENTRY(tasks_todo.list.next, struct ta_task, list);
		if (task)
			list_unlink(&task->list);

		/* free the lock so more tasks can be added */
		ret = pthread_mutex_unlock(&todo_list_mutex);
		if (ret != 0) {
			OT_LOG(LOG_ERR, "Failed to unlock the mutex");
			continue;
		}

		/* Exctract messagese part */
		if (!task || com_get_msg_name(task->msg, &com_msg_name))
			continue;

		switch (com_msg_name) {

		case COM_MSG_NAME_OPEN_SESSION:
			open_session(task);
			break;

		case COM_MSG_NAME_INVOKE_CMD:
			invoke_cmd(task);
			break;

		case COM_MSG_NAME_CLOSE_SESSION:
			close_session(task);
			break;

		default:
			/* Just logging an error and message will be ignored */
			OT_LOG(LOG_ERR, "Unknow message, ignore");
			continue;
		}
	}

	/* should never reach here */
	exit(TA_EXIT_PANICKED);
	return NULL;
}
