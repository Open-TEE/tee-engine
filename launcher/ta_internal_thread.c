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
#include "tee_cancellation.h"
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
#define TEEC_MEM_INPUT			0x00000001
#define TEEC_MEM_OUTPUT			0x00000002


#define SESSION_STATE_ACTIVE		0x000000F0

struct __TEE_TASessionHandle {
	uint64_t sess_id;
	uint8_t session_state;
};

struct ta_shared_mem {
	char shm_uuid[SHM_MEM_NAME_LEN];
	void *addr;
	uint32_t original_size;
	uint32_t type; /* TEE_PARAM_XXXX */
};

#define INIT_TA_SHM_STRUCT(ta_shm_struct)			\
	do {							\
		(ta_shm_struct).addr = MAP_FAILED;		\
		(ta_shm_struct).type = TEE_PARAM_TYPE_NONE;	\
	} while (0);

#define FOR_EACH_TA_SHM(i) for (i = 0; i < 4; ++i)

/*!
 *  \brief Iterate over TA parameters
 *  \param i interger
 */
#define FOR_EACH_TA_PARAM(i) for (i = 0; i < 4; ++i)

static bool set_exec_operation_id(uint64_t new_op_id)
{
	/* Lock task queue from logic thread */
	if (pthread_mutex_lock(&executed_operation_id_mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock the mutex")
		return false;
	}

	if (new_op_id != 0) {
		mask_cancellation();
		cancellation_flag = false;
	}

	executed_operation_id = new_op_id;

	if (pthread_mutex_unlock(&executed_operation_id_mutex))
		OT_LOG(LOG_ERR, "Failed to lock the mutex")

	return true;
}

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

static void free_shm_and_from_manager(struct ta_shared_mem *ta_shm_mem)
{
	struct com_msg_unlink_shm_region *unlink_msg = NULL;
	struct ta_task *new_ta_task = NULL;

	if (!(ta_shm_mem->type == TEE_PARAM_TYPE_MEMREF_INOUT ||
	      ta_shm_mem->type == TEE_PARAM_TYPE_MEMREF_INPUT ||
	      ta_shm_mem->type == TEE_PARAM_TYPE_MEMREF_OUTPUT)) {
		OT_LOG(LOG_ERR, "Unknow memory type")
		return;
	}

	/* Update memory type */
	ta_shm_mem->type = TEE_PARAM_TYPE_NONE;

	/* Free memory area. Use original size */
	if (ta_shm_mem->addr != MAP_FAILED)
		munmap(ta_shm_mem->addr, ta_shm_mem->original_size);

	/* Unregister shared memory */
	new_ta_task = calloc(1, sizeof(struct ta_task));
	if (!new_ta_task) {
		OT_LOG(LOG_ERR, "out of memory");
		return; /* Note: Shared memory is not unlinked */
	}

	new_ta_task->msg_len = sizeof(struct com_msg_unlink_shm_region);
	new_ta_task->msg = calloc(1, new_ta_task->msg_len);
	if (!new_ta_task->msg) {
		OT_LOG(LOG_ERR, "out of memory");
		free(new_ta_task);
		return; /* Note: Shared memory is not unlinked */
	}

	unlink_msg = new_ta_task->msg;
	unlink_msg->msg_hdr.msg_name = COM_MSG_NAME_UNLINK_SHM_REGION;
	unlink_msg->msg_hdr.msg_type = COM_TYPE_QUERY;
	unlink_msg->msg_hdr.sess_id = 0; /* Not used */
	memcpy(unlink_msg->name, ta_shm_mem->shm_uuid, SHM_MEM_NAME_LEN);

	add_msg_done_queue_and_notify(new_ta_task);
}

static void free_all_shm(struct ta_shared_mem *ta_shm_mem)
{
	int i;

	FOR_EACH_TA_SHM(i) {

		if (ta_shm_mem[i].type == TEE_PARAM_TYPE_NONE)
			continue;

		free_shm_and_from_manager(&ta_shm_mem[i]);
	}
}

static void ta2ta_com_msg_op_to_params(uint32_t paramTypes, TEE_Param *params,
				       struct ta_shared_mem *ta_shm_mem,
				       struct com_msg_operation *operation)
{
	int i;

	FOR_EACH_TA_SHM(i) {

		if (TEE_PARAM_TYPE_GET(paramTypes, i) == TEE_PARAM_TYPE_VALUE_INOUT ||
		    TEE_PARAM_TYPE_GET(paramTypes, i) == TEE_PARAM_TYPE_VALUE_OUTPUT) {
			memcpy(&params[i].value, &operation->params[i].param.value,
			       sizeof(sizeof(params[i].value)));

		} else if (TEE_PARAM_TYPE_GET(paramTypes, i) == TEE_PARAM_TYPE_MEMREF_INOUT ||
			   TEE_PARAM_TYPE_GET(paramTypes, i) == TEE_PARAM_TYPE_MEMREF_OUTPUT) {

			params[i].memref.size = operation->params[i].param.memref.size;

			/* Special case. If original size has been zero,
			 * no shm aquired or data trasnfered*/
			if (!ta_shm_mem[i].original_size)
				continue;

			/* Memory is not closed, just copy.. */
			memcpy(params[i].memref.buffer, ta_shm_mem[i].addr, params[i].memref.size);
		}

		/* Note: No data if parameter type is NONE or INPUT */
	}
}

static TEE_Result get_shm_from_manager_and_map_region(struct ta_shared_mem *ta_shm_mem)
{
	struct com_msg_open_shm_region *open_shm = NULL;
	struct ta_task *new_ta_task = NULL;
	TEE_Result ret = TEE_SUCCESS;
	int fd;

	/* Unregister shared memory */
	new_ta_task = calloc(1, sizeof(struct ta_task));
	if (!new_ta_task) {
		OT_LOG(LOG_ERR, "out of memory")
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	new_ta_task->msg_len = sizeof(struct com_msg_open_shm_region);
	new_ta_task->msg = calloc(1, new_ta_task->msg_len);
	if (!new_ta_task->msg) {
		OT_LOG(LOG_ERR, "out of memory")
		free(new_ta_task);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	open_shm = new_ta_task->msg;
	open_shm->msg_hdr.msg_name = COM_MSG_NAME_OPEN_SHM_REGION;
	open_shm->msg_hdr.msg_type = COM_TYPE_QUERY;
	open_shm->msg_hdr.sess_id = 0; /* Not used */
	open_shm->size = ta_shm_mem->original_size;

	add_msg_done_queue_and_notify(new_ta_task);

	if (!wait_response_msg())
		return TEE_ERROR_GENERIC;

	/* We can reuse open_shm pointer, because after send it is freed */
	open_shm = response_msg;
	response_msg = NULL;

	if (open_shm->msg_hdr.msg_name != COM_MSG_NAME_OPEN_SHM_REGION) {

		if (!get_vals_from_err_msg(response_msg, &ret, NULL)) {
			OT_LOG(LOG_ERR, "Received unknown message");
			ret = TEE_ERROR_GENERIC;
		}

		/* Received error message */
		goto err;
	}

	if (open_shm->return_code != TEE_SUCCESS)
		goto err;

	memcpy(ta_shm_mem->shm_uuid, open_shm->name, SHM_MEM_NAME_LEN);

	fd = shm_open(ta_shm_mem->shm_uuid, (O_RDWR | O_RDONLY), 0);
	if (fd == -1) {
		OT_LOG(LOG_ERR, "Failed to open the shared memory area : %d", errno);
		ret = TEEC_ERROR_GENERIC;
		goto err;
	}

	ta_shm_mem->addr = mmap(NULL, ta_shm_mem->original_size,
			       (PROT_WRITE | PROT_READ), MAP_SHARED, fd, 0);
	if (ta_shm_mem->addr == MAP_FAILED) {
		OT_LOG(LOG_ERR, "Failed to MMAP");
		ret = TEEC_ERROR_OUT_OF_MEMORY;
		free_shm_and_from_manager(ta_shm_mem);
	}

	close(fd);

err:
	free(response_msg);
	return ret;
}

static TEE_Result map_and_cpy_parameters(uint32_t paramTypes, TEE_Param *params,
					 struct ta_shared_mem *ta_shm_mems,
					 struct com_msg_operation *operation)
{
	TEE_Result ret = TEE_SUCCESS;
	int i;

	memset(operation, 0, sizeof(struct com_msg_operation));

	FOR_EACH_TA_SHM(i) {

		if (TEE_PARAM_TYPE_GET(paramTypes, i) == TEE_PARAM_TYPE_NONE)
			continue;

		if (TEE_PARAM_TYPE_GET(paramTypes, i) == TEE_PARAM_TYPE_VALUE_INOUT ||
		    TEE_PARAM_TYPE_GET(paramTypes, i) == TEE_PARAM_TYPE_VALUE_INPUT ||
		    TEE_PARAM_TYPE_GET(paramTypes, i) == TEE_PARAM_TYPE_VALUE_OUTPUT) {
			memcpy(&operation->params[i].param.value,
			       &params[i].value, sizeof(params[i].value));
			continue;
		}

		/*
		 * Because it is not value, parameter type is MEMREF
		 */

		/* Check parameters */
		if (!params[i].memref.size && params[i].memref.buffer) {
			OT_LOG(LOG_ERR, "Error: Buffer size-param is ZERO and "
			       "buffer-param is not NULL");
			ret = TEE_ERROR_BAD_PARAMETERS;
			break;
		}

		if (!params[i].memref.buffer && params[i].memref.size) {
			OT_LOG(LOG_ERR, "Error: Buffer-param is NULL and size-param is not NULL");
			ret = TEE_ERROR_BAD_PARAMETERS;
			break;
		}

		/* Original size is size that will be used map the mem pages */
		ta_shm_mems[i].original_size = params[i].memref.size;
		ta_shm_mems[i].type = TEE_PARAM_TYPE_GET(paramTypes, i);

		/* Zero size is special case */
		if (!params[i].memref.size) {
			operation->params[i].param.memref.size = params->memref.size;
			continue;
		}

		ret = get_shm_from_manager_and_map_region(&ta_shm_mems[i]);
		if (ret != TEE_SUCCESS)
			break;

		/* Copy parameter buffer */
		memcpy(ta_shm_mems[i].addr, params[i].memref.buffer, params[i].memref.size);
		operation->params[i].param.memref.size = params[i].memref.size;

		/* Copy shm uuid to operation */
		memcpy(operation->params[i].param.memref.shm_area,
		       ta_shm_mems[i].shm_uuid, SHM_MEM_NAME_LEN);
	}

	operation->paramTypes = paramTypes;

	if (ret != TEE_SUCCESS)
		free_all_shm(ta_shm_mems);

	return ret;
}

static TEE_Result wait_and_handle_open_sess_resp(uint32_t paramTypes, TEE_Param params[4],
						 TEE_TASessionHandle *session,
						 uint32_t *returnOrigin,
						 struct ta_shared_mem *ta_shm_mem)
{
	struct com_msg_open_session *resp_open_msg = NULL;
	TEE_Result ret;

	if (!wait_response_msg())
		goto err_com;

	resp_open_msg = response_msg;
	response_msg = NULL;

	if (resp_open_msg->msg_hdr.msg_name != COM_MSG_NAME_OPEN_SESSION) {

		if (!get_vals_from_err_msg(response_msg, &ret, returnOrigin)) {
			OT_LOG(LOG_ERR, "Received unknown message")
			goto err_com;
		}

		goto err_msg;
	}

	/* Copy parameters and close them */
	ta2ta_com_msg_op_to_params(paramTypes, params, ta_shm_mem, &resp_open_msg->operation);
	free_all_shm(ta_shm_mem);

	/* Get return origin and return code */
	ret = resp_open_msg->return_code_open_session;
	if (returnOrigin)
		*returnOrigin = resp_open_msg->return_origin;

	if (ret != TEE_SUCCESS)
		goto err_ret; /* Open session was not success, free session and set it NULL */

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

static void wait_and_handle_close_session_resp(TEE_TASessionHandle session)
{
	struct com_msg_open_session *resp_close_msg = NULL;

	if (!wait_response_msg())
		return;

	resp_close_msg = response_msg;
	response_msg = NULL;

	/* Logging. Message is not containing any information */
	if (resp_close_msg->msg_hdr.msg_name == COM_MSG_NAME_CLOSE_SESSION) {
		/* Fine */

	} else if (resp_close_msg->msg_hdr.msg_name == COM_MSG_NAME_ERROR) {
		OT_LOG(LOG_ERR, "Received error message")

	} else {
		OT_LOG(LOG_ERR, "Received unknow message")
	}

	free(session);
	free(resp_close_msg);
}

static TEE_Result wait_and_handle_invoke_cmd_resp(uint32_t paramTypes, TEE_Param params[4],
						  uint32_t *returnOrigin,
						  struct ta_shared_mem *ta_shm_mem)
{
	struct com_msg_invoke_cmd *resp_invoke_msg = NULL;
	TEE_Result ret;

	if (!wait_response_msg())
		goto err_com;

	resp_invoke_msg = response_msg;
	response_msg = NULL;

	if (resp_invoke_msg->msg_hdr.msg_name != COM_MSG_NAME_INVOKE_CMD) {

		if (!get_vals_from_err_msg(response_msg, &ret, returnOrigin)) {
			OT_LOG(LOG_ERR, "Received unknown message")
			goto err_com;
		}

		goto err_msg;
	}

	ta2ta_com_msg_op_to_params(paramTypes, params, ta_shm_mem, &resp_invoke_msg->operation);
	free_all_shm(ta_shm_mem);

	if (returnOrigin)
		*returnOrigin = resp_invoke_msg->return_origin;
	ret = resp_invoke_msg->return_code;
	free(resp_invoke_msg);

	return ret;

err_com:
	if (returnOrigin)
		*returnOrigin = TEE_ORIGIN_COMMS;
	ret = TEEC_ERROR_COMMUNICATION;

err_msg:
	free(resp_invoke_msg);
	return ret;
}

static int open_shared_mem(const char *name, void **buffer, uint32_t size, bool isOutput)
{
	int flag = 0;
	int fd;
	void *address = NULL;
	struct stat file_stat;

	if (!name || !buffer) {
		OT_LOG(LOG_ERR, "Invalid pointer");
		goto errorExit;
	}

	if (size == 0)
		return 0;

	if (isOutput)
		flag |= O_RDONLY; /* It is an outbuffer only so we just need read access */
	else
		flag |= O_RDWR;

	fd = shm_open(name, flag, 0);
	if (fd == -1) {
		OT_LOG(LOG_ERR, "Failed to open the shared memory area : %d", errno);
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

static TEE_Result copy_params_to_com_msg_op(struct com_msg_operation *operation, TEE_Param *params,
					    int32_t tee_param_types)
{
	TEE_Result ret = TEE_SUCCESS;
	int i;

	FOR_EACH_TA_PARAM(i) {

		if (TEE_PARAM_TYPE_GET(tee_param_types, i) == TEE_PARAM_TYPE_VALUE_OUTPUT ||
		    TEE_PARAM_TYPE_GET(tee_param_types, i) == TEE_PARAM_TYPE_VALUE_INOUT) {

			/* We only have to copy back the output values, because the memory
			 * types point to shared memory so they are updated directly in place.
			 */
			memcpy(&operation->params[i].param.value,
			       &params[i].value,
			       sizeof(params[i].value));

		} else if (TEE_PARAM_TYPE_GET(tee_param_types, i) == TEE_PARAM_TYPE_MEMREF_INPUT ||
			   TEE_PARAM_TYPE_GET(tee_param_types, i) == TEE_PARAM_TYPE_MEMREF_OUTPUT ||
			   TEE_PARAM_TYPE_GET(tee_param_types, i) == TEE_PARAM_TYPE_MEMREF_INOUT) {

			/* Unmap the shared memory regions as they are no longer valid for the TA.
			 * Will be using original size. Original size is size which was used in
			 * mmap-command. If TA will change size parameter, we might end up with
			 * memory leak */
			if (operation->params[i].param.memref.size != 0 &&
			    params[i].memref.buffer) {
				munmap(params[i].memref.buffer,
				       operation->params[i].param.memref.size);

				/* If TA is not crashed, return short buffer */
				if (params[i].memref.size > operation->params[i].param.memref.size)
					ret = TEE_ERROR_SHORT_BUFFER;
			}

			operation->params[i].param.memref.size = params[i].memref.size;
		}
	}

	return ret;
}

static void map_TEEC_param_types_to_TEE(struct com_msg_operation *operation, uint32_t *TEE_types)
{
	int types[4] = {0}, i;

	FOR_EACH_TA_PARAM(i) {

		/* convert the TEEC types to the TEE internal types */
		if (TEE_PARAM_TYPE_GET(operation->paramTypes, i) == TEEC_NONE ) {

			types[i] = TEE_PARAM_TYPE_NONE;

		} else if (TEE_PARAM_TYPE_GET(operation->paramTypes, i) == TEEC_VALUE_INOUT) {

			types[i] = TEE_PARAM_TYPE_VALUE_INOUT;

		} else if (TEE_PARAM_TYPE_GET(operation->paramTypes, i) == TEEC_VALUE_INPUT) {

			types[i] = TEE_PARAM_TYPE_VALUE_INPUT;

		} else if (TEE_PARAM_TYPE_GET(operation->paramTypes, i) == TEEC_VALUE_OUTPUT) {

			types[i] = TEE_PARAM_TYPE_VALUE_OUTPUT;

		} else if (TEE_PARAM_TYPE_GET(operation->paramTypes, i) == TEEC_VALUE_INOUT) {
			types[i] = TEE_PARAM_TYPE_VALUE_INOUT;

		} else if (TEE_PARAM_TYPE_GET(operation->paramTypes, i) == TEEC_VALUE_OUTPUT) {
			types[i] = TEE_PARAM_TYPE_VALUE_OUTPUT;

		} else if (TEE_PARAM_TYPE_GET(operation->paramTypes, i) == TEEC_VALUE_INPUT) {
			types[i] = TEE_PARAM_TYPE_VALUE_INPUT;

		} else if (TEE_PARAM_TYPE_GET(operation->paramTypes, i) == TEEC_MEMREF_PARTIAL_INOUT ||
			   TEE_PARAM_TYPE_GET(operation->paramTypes, i) == TEEC_MEMREF_TEMP_INOUT ||
			   TEE_PARAM_TYPE_GET(operation->paramTypes, i) == TEE_PARAM_TYPE_MEMREF_INOUT) {

			types[i] = TEE_PARAM_TYPE_MEMREF_INOUT;

		} else if (TEE_PARAM_TYPE_GET(operation->paramTypes, i) == TEEC_MEMREF_PARTIAL_INPUT ||
			   TEE_PARAM_TYPE_GET(operation->paramTypes, i) == TEEC_MEMREF_TEMP_INPUT ||
			   TEE_PARAM_TYPE_GET(operation->paramTypes, i) == TEE_PARAM_TYPE_MEMREF_INPUT) {

			types[i] = TEE_PARAM_TYPE_MEMREF_INPUT;

		} else if (TEE_PARAM_TYPE_GET(operation->paramTypes, i) == TEEC_MEMREF_PARTIAL_OUTPUT ||
			   TEE_PARAM_TYPE_GET(operation->paramTypes, i) == TEEC_MEMREF_TEMP_OUTPUT ||
			   TEE_PARAM_TYPE_GET(operation->paramTypes, i) == TEE_PARAM_TYPE_MEMREF_OUTPUT) {

			types[i] = TEE_PARAM_TYPE_MEMREF_OUTPUT;

		} else if (TEE_PARAM_TYPE_GET(operation->paramTypes, i) == TEEC_MEMREF_WHOLE) {

			if (operation->params[i].flags & TEEC_MEM_INPUT)
				types[i] = TEE_PARAM_TYPE_MEMREF_INPUT;
			if (operation->params[i].flags & TEEC_MEM_OUTPUT)
				types[i] = TEE_PARAM_TYPE_MEMREF_OUTPUT;
			if (operation->params[i].flags & (TEEC_MEM_INPUT | TEEC_MEM_OUTPUT))
				types[i] = TEE_PARAM_TYPE_MEMREF_INOUT;

		} else {
			OT_LOG(LOG_ERR, "Warning: Unknow parameter type")
		}
	}

	*TEE_types = TEE_PARAM_TYPES(types[0], types[1], types[2], types[3]);
}

static int copy_com_msg_op_to_param(struct com_msg_operation *operation, TEE_Param *params,
				    uint32_t *tee_param_types)
{
	uint32_t param_types = operation->paramTypes;
	bool isOutput;
	int ret = 0, i;

	memset(params, 0, 4 * sizeof(TEE_Param));

	FOR_EACH_TA_PARAM(i) {

		if (TEE_PARAM_TYPE_GET(param_types, i) == TEEC_NONE ||
		    TEE_PARAM_TYPE_GET(param_types, i) == TEEC_VALUE_OUTPUT ||
		    TEE_PARAM_TYPE_GET(param_types, i) == TEE_PARAM_TYPE_VALUE_OUTPUT) {
			continue;

		} else if (TEE_PARAM_TYPE_GET(param_types, i) == TEEC_VALUE_INPUT ||
			   TEE_PARAM_TYPE_GET(param_types, i) == TEEC_VALUE_INOUT ||
			   TEE_PARAM_TYPE_GET(param_types, i) == TEE_PARAM_TYPE_VALUE_INOUT ||
			   TEE_PARAM_TYPE_GET(param_types, i) == TEE_PARAM_TYPE_VALUE_INPUT) {

			memcpy(&params[i].value,
			       &operation->params[i].param.value, sizeof(params[i].value));

		} else {

			/* determine if this is a readonly memory area */
			if (TEE_PARAM_TYPE_GET(param_types, i) == TEEC_MEMREF_TEMP_OUTPUT ||
			    TEE_PARAM_TYPE_GET(param_types, i) == TEEC_MEMREF_PARTIAL_OUTPUT ||
			    TEE_PARAM_TYPE_GET(param_types, i) == TEE_PARAM_TYPE_MEMREF_OUTPUT) {
				isOutput = true;
			} else {
				isOutput = false;
			}

			params[i].memref.size = operation->params[i].param.memref.size;

			/* if there is some failure opening the shared memory just fail graefully */
			if (open_shared_mem(operation->params[i].param.memref.shm_area,
					    &params[i].memref.buffer,
					    operation->params[i].param.memref.size,
					    isOutput) == -1)
				ret = -1;
		}
	}

	map_TEEC_param_types_to_TEE(operation, tee_param_types);

	if (ret == -1) /* clean up all memory that has been mmaped because of the error */
		copy_params_to_com_msg_op(operation, params, *tee_param_types);

	return ret;
}

static void open_session(struct ta_task *in_task)
{
	struct com_msg_open_session *open_msg = in_task->msg;
	uint32_t paramTypes;
	TEE_Param params[4];
	TEE_Result ret;

	if (open_msg->msg_hdr.msg_name != COM_MSG_NAME_OPEN_SESSION ||
	    open_msg->msg_hdr.msg_type != COM_TYPE_QUERY) {
		OT_LOG(LOG_ERR, "Invalid message, ignore");
		free_task(in_task);
		return;
	}

	if (!set_exec_operation_id(open_msg->operation.operation_id)) {
		open_msg->return_code_open_session = TEE_ERROR_GENERIC;
		open_msg->return_origin = TEE_ORIGIN_TEE;
		goto out;
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

	set_exec_operation_id(0);

	/* Copy the data back from the TA to the client */
	ret = copy_params_to_com_msg_op(&open_msg->operation, params, paramTypes);
	if  (ret != TEEC_SUCCESS)
		open_msg->return_code_open_session = ret;

	open_msg->return_origin = TEE_ORIGIN_TRUSTED_APP;
out:
	open_msg->msg_hdr.msg_type = COM_TYPE_RESPONSE;
	add_msg_done_queue_and_notify(in_task);
}

static void invoke_cmd(struct ta_task *in_task)
{
	struct com_msg_invoke_cmd *invoke_msg = in_task->msg;
	uint32_t paramTypes;
	TEE_Param params[4];
	TEE_Result ret;

	if (invoke_msg->msg_hdr.msg_name != COM_MSG_NAME_INVOKE_CMD ||
	    invoke_msg->msg_hdr.msg_type != COM_TYPE_QUERY) {
		OT_LOG(LOG_ERR, "Invalid message, ignore");
		free_task(in_task);
		return;
	}

	if (!set_exec_operation_id(invoke_msg->operation.operation_id)) {
		invoke_msg->return_code = TEE_ERROR_GENERIC;
		invoke_msg->return_origin = TEE_ORIGIN_TEE;
		goto out;
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

	set_exec_operation_id(0);

	/* Copy the data back from the TA to the client */
	ret = copy_params_to_com_msg_op(&invoke_msg->operation, params, paramTypes);
	if (ret != TEEC_SUCCESS)
		invoke_msg->return_code = ret;

	invoke_msg->return_origin = TEE_ORIGIN_TRUSTED_APP;
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
				     uint32_t paramTypes, TEE_Param *params,
				     TEE_TASessionHandle *session, uint32_t *returnOrigin)
{
	struct ta_task *new_ta_task = NULL;
	struct com_msg_open_session *open_msg = NULL;
	struct ta_shared_mem ta_shm[4];
	TEE_Result ret = TEE_ERROR_GENERIC;
	int i;

	/* TODO: cancel timeout */
	if (cancellationRequestTimeout != TEE_TIMEOUT_INFINITE) {
		OT_LOG(LOG_ERR, "Timeout not implemented. Must be TEE_TIMEOUT_INFINITE");
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	if (!destination || !session) {
		OT_LOG(LOG_ERR, "Destination or session NULL");
		if (returnOrigin)
			*returnOrigin = TEE_ORIGIN_TEE;
		return TEE_ERROR_GENERIC;
	}

	/* Initialize used ta shared memorys */
	FOR_EACH_TA_SHM(i) {
		INIT_TA_SHM_STRUCT(ta_shm[i])
	}

	*session = calloc(1, sizeof(struct __TEE_TASessionHandle));
	if (!*session) {
		OT_LOG(LOG_ERR, "out of memory")
		goto err_1;
	}

	new_ta_task = calloc(1, sizeof(struct ta_task));
	if (!new_ta_task) {
		OT_LOG(LOG_ERR, "Out of memory");
		goto err_2;
	}

	new_ta_task->msg_len = sizeof(struct com_msg_open_session);
	new_ta_task->msg = calloc(1, new_ta_task->msg_len);
	if (!new_ta_task->msg) {
		OT_LOG(LOG_ERR, "Out of memory");
		goto err_3;
	}

	open_msg = new_ta_task->msg;

	ret = map_and_cpy_parameters(paramTypes, params, ta_shm, &open_msg->operation);
	if (ret != TEE_SUCCESS)
		goto err_4; /* Err logged */

	/* Message header */
	open_msg->msg_hdr.msg_name = COM_MSG_NAME_OPEN_SESSION;
	open_msg->msg_hdr.msg_type = COM_TYPE_QUERY;
	open_msg->msg_hdr.sess_id = 0;
	open_msg->operation.operation_id = 0;

	memcpy(&open_msg->uuid, destination, sizeof(TEE_UUID));

	add_msg_done_queue_and_notify(new_ta_task);

	return wait_and_handle_open_sess_resp(paramTypes, params, session, returnOrigin, ta_shm);

err_4:
	free(new_ta_task->msg);
err_3:
	free(new_ta_task);
err_2:
	free(*session);
err_1:
	*session = NULL;
	if (returnOrigin)
		*returnOrigin = TEE_ORIGIN_TEE;
	return ret;
}

void ta_close_ta_session(TEE_TASessionHandle session)
{
	struct ta_task *new_ta_task = NULL;

	if (!session || session->session_state != SESSION_STATE_ACTIVE) {
		OT_LOG(LOG_ERR, "Session NULL or not opened")
		return;
	}

	new_ta_task = calloc(1, sizeof(struct ta_task));
	if (!new_ta_task) {
		OT_LOG(LOG_ERR, "Out of memory");
		return;
	}

	new_ta_task->msg_len = sizeof(struct com_msg_close_session);
	new_ta_task->msg = calloc(1, new_ta_task->msg_len);
	if (!new_ta_task->msg) {
		OT_LOG(LOG_ERR, "Out of memory");
		free(new_ta_task);
		return;
	}

	/* Message header */
	((struct com_msg_close_session *)new_ta_task->msg)->msg_hdr.msg_name =
			COM_MSG_NAME_CLOSE_SESSION;
	((struct com_msg_close_session *)new_ta_task->msg)->msg_hdr.msg_type = COM_TYPE_QUERY;
	((struct com_msg_close_session *)new_ta_task->msg)->msg_hdr.sess_id = session->sess_id;

	add_msg_done_queue_and_notify(new_ta_task);

	wait_and_handle_close_session_resp(session);
}

TEE_Result ta_invoke_ta_command(TEE_TASessionHandle session,
				       uint32_t cancellationRequestTimeout,
				       uint32_t commandID, uint32_t paramTypes, TEE_Param *params,
				       uint32_t *returnOrigin)
{
	struct ta_task *new_ta_task = NULL;
	struct com_msg_invoke_cmd *invoke_msg = NULL;
	struct ta_shared_mem ta_shm[4];
	TEE_Result ret = TEE_ERROR_GENERIC;
	int i;

	/* TODO: cancel timeout */
	if (cancellationRequestTimeout != TEE_TIMEOUT_INFINITE) {
		OT_LOG(LOG_ERR, "Timeout not implemented. Must be TEE_TIMEOUT_INFINITE");
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	if (!session || session->session_state != SESSION_STATE_ACTIVE) {
		OT_LOG(LOG_ERR, "Session NULL or not opened")
		goto err_1;
	}

	/* Initialize used ta shared memorys */
	FOR_EACH_TA_SHM(i) {
		INIT_TA_SHM_STRUCT(ta_shm[i])
	}

	new_ta_task = calloc(1, sizeof(struct ta_task));
	if (!new_ta_task) {
		OT_LOG(LOG_ERR, "Out of memory");
		goto err_1;
	}

	new_ta_task->msg_len = sizeof(struct com_msg_invoke_cmd);
	new_ta_task->msg = calloc(1, new_ta_task->msg_len);
	if (!new_ta_task->msg) {
		OT_LOG(LOG_ERR, "Out of memory");
		goto err_1;
	}

	invoke_msg = new_ta_task->msg;

	ret = map_and_cpy_parameters(paramTypes, params, ta_shm, &invoke_msg->operation);
	if (ret != TEE_SUCCESS)
		goto err_2; /* Err logged */

	/* Message header */
	invoke_msg->msg_hdr.msg_name = COM_MSG_NAME_INVOKE_CMD;
	invoke_msg->msg_hdr.msg_type = COM_TYPE_QUERY;
	invoke_msg->msg_hdr.sess_id = session->sess_id;
	invoke_msg->cmd_id = commandID;
	invoke_msg->operation.operation_id = 0;

	add_msg_done_queue_and_notify(new_ta_task);

	return wait_and_handle_invoke_cmd_resp(paramTypes, params, returnOrigin, ta_shm);

err_2:
	free_task(new_ta_task);
err_1:
	free(new_ta_task);
	if (returnOrigin)
		*returnOrigin = TEE_ORIGIN_TEE;
	return TEE_ERROR_GENERIC;
}

bool get_cancellation_flag()
{
	if (!cancellation_mask)
		return cancellation_flag;

	return false;
}

bool mask_cancellation()
{
	bool ret = cancellation_mask;

	cancellation_mask = true;

	return ret;
}

bool unmask_cancellation()
{
	bool ret = cancellation_mask;

	cancellation_mask = false;

	return ret;
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
