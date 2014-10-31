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

#include <pthread.h>
#include <unistd.h>

#include "com_protocol.h"
#include "extern_resources.h"
#include "io_thread.h"
#include "tee_list.h"
#include "tee_logging.h"
#include "logic_thread.h"

static void free_proc(proc_t del_proc)
{
	del_proc = del_proc;
}

static void add_msg_done_queue_and_notify(struct manager_msg *man_msg)
{
	const uint64_t event = 1;

	/* Lock task queue from logic thread */
	if (pthread_mutex_lock(&done_queue_mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock the mutex");
		return;
	}

	/* enqueue the task manager queue */
	list_add_before(&man_msg->list, &done_queue.list);

	if (pthread_mutex_unlock(&done_queue_mutex)) {
		/* For now, just log error */
		OT_LOG(LOG_ERR, "Failed to lock the mutex");
	}

	/* notify the I/O thread that there is something at output queue */
	if (write(event_done_queue_fd, &event, sizeof(uint64_t)) == -1) {
		OT_LOG(LOG_ERR, "Failed to notify the io thread");
		/* TODO/PLACEHOLDER: notify IO thread */
	}
}

static void gen_err_msg_and_add_to_done(struct manager_msg *man_msg,
										uint32_t err_origin, uint32_t err_name)
{
	free(man_msg->msg); /* replace old message with error */

	man_msg->msg = calloc(1, sizeof(struct com_msg_error));
	if (!man_msg->msg) {
		OT_LOG(LOG_ERR, "Out of memory");
		return;
	}

	man_msg->msg_len = sizeof(struct com_msg_error);

	/* Fill error message */
	((struct com_msg_error *) man_msg->msg)->msg_hdr.msg_name = COM_MSG_NAME_ERROR;
	((struct com_msg_error *) man_msg->msg)->ret_origin = err_origin;
	((struct com_msg_error *) man_msg->msg)->ret = err_name;

	add_msg_done_queue_and_notify(man_msg);
}

static void ca_init_context(struct manager_msg *man_msg)
{
	struct com_msg_ca_init_tee_conn *init_msg;

	if (!man_msg)
		return;

	init_msg = man_msg->msg;

	/* Valid init message */
	if (init_msg->msg_hdr.msg_name != COM_MSG_NAME_CA_INIT_CONTEXT ||
		init_msg->msg_hdr.msg_type != COM_TYPE_QUERY) {
		OT_LOG(LOG_ERR, "Parsing wrong message, ignore msg");
		goto discard_msg;
	}

	/* Message can be received only from client */
	if (man_msg->proc->p_type != proc_t_CA) {
		OT_LOG(LOG_ERR, "Message can be received only from clientApp");
		goto discard_msg;
	}

	/* Valid message. Updated CA proc status to initialized */
	man_msg->proc->content.process.status = proc_initialized;

	/* Response to CA */
	init_msg->msg_hdr.msg_type = COM_TYPE_RESPONSE;
	init_msg->ret = TEE_SUCCESS;

	add_msg_done_queue_and_notify(man_msg);

	return;

discard_msg:
	free(man_msg);
}

static void open_session_response(struct manager_msg *man_msg)
{
	man_msg = man_msg;
}

static void get_next_sess_id(uint64_t *new_id)
{
	/* TODO: Rare, but after ~92 quadrillion session this will overflow */
	static uint64_t next_sess_id;

	*new_id = next_sess_id++;
}

static int launch_and_init_ta(struct manager_msg *man_msg, TEE_UUID *ta_uuid,
				  proc_t *new_ta_proc, proc_t conn_ta)
{
	man_msg = man_msg;
	ta_uuid = ta_uuid;
	new_ta_proc = new_ta_proc;
	conn_ta = conn_ta;

	return 0;
}

static int create_sesLink(proc_t owner, proc_t to, uint64_t sess_id)
{
	owner = owner;
	to = to;
	sess_id = sess_id;

	return 0;
}

static void open_session_query(struct manager_msg *man_msg)
{
	proc_t new_ta = NULL;
	proc_t conn_ta = NULL;
	uint64_t new_session_id;
	struct com_msg_open_session *open_msg = man_msg->msg;

	/* Generate new session ID */
	get_next_sess_id(&new_session_id);

	/* SessID is needed when message is sent back from TA */
	open_msg->msg_hdr.sess_id = new_session_id;

	/* Launch new TA, if needed */
	if (launch_and_init_ta(man_msg, &open_msg->uuid, &new_ta, conn_ta))
		return; /* Err msg logged and send to sender */

	/* If new_ta is NULL, should connect existing TA (conn_ta is not NULL)
	 * If conn_ta is NULL, new ta created and connect to that  (new_ta is not null)
	 * If conn_ta is NULL and new_ta NULL, should never happen */

	/* Send invoke task to TA */
	if (conn_ta) {

		if (create_sesLink(man_msg->proc, conn_ta, new_session_id))
			goto err; /* Err msg logged */

		/* Pass on open session cmd
		 * Know error: If this message send fails, CA will be waiting forever, because
		 * no error message is not send */
		man_msg->proc = conn_ta;
		add_msg_done_queue_and_notify(man_msg);

	} else if (new_ta) {

		if (create_sesLink(man_msg->proc, new_ta, new_session_id))
			goto err; /* Err msg logged */

		/* Open session command is already send */

		free_manager_msg(man_msg); /* TA will send response message */

	} else {
		/* Should never end up here ! */
		OT_LOG(LOG_ERR, "Error");
		goto err;
	}

	return;

err:
	free_proc(new_ta);
	gen_err_msg_and_add_to_done(man_msg, TEE_ORIGIN_TEE, TEE_ERROR_GENERIC);
}

static void open_session_msg(struct manager_msg *man_msg)
{
	struct com_msg_open_session *open_msg = man_msg->msg;

	if (open_msg->msg_hdr.msg_name != COM_MSG_NAME_OPEN_SESSION) {
		OT_LOG(LOG_ERR, "Handling wrong message");
		goto discard_msg;
	}

	/* Function is only valid for proc FDs */
	if (man_msg->proc->p_type >= proc_t_last ||
	    man_msg->proc->content.process.status != proc_initialized) {
		OT_LOG(LOG_ERR, "Invalid connection type or status")
		goto discard_msg;
	}

	/* Query and response will handle in their own functions */
	if (open_msg->msg_hdr.msg_type == COM_TYPE_QUERY) {
		open_session_query(man_msg);

	} else if (open_msg->msg_hdr.msg_type == COM_TYPE_RESPONSE) {
		open_session_response(man_msg);

	} else {
		OT_LOG(LOG_ERR, "Unkwon message type");
		goto discard_msg;
	}

	return;

discard_msg:
	free_manager_msg(man_msg);
}

void *logic_thread_mainloop(void *arg)
{
	arg = arg; /* ignored */
	struct manager_msg *handled_msg;
	uint8_t com_msg_name;

	while (1) {

		if (pthread_mutex_lock(&todo_queue_mutex)) {
			OT_LOG(LOG_ERR, "Failed to lock the mutex");
			continue;
		}

		/* Wait for message */
		while (list_is_empty(&todo_queue.list)) {
			if (pthread_cond_wait(&todo_queue_cond, &todo_queue_mutex)) {
				OT_LOG(LOG_ERR, "Failed to wait for condition");
				continue;
			}
		}

		/* Queue is FIFO and therefore get just fist message */
		handled_msg = LIST_ENTRY(todo_queue.list.next, struct manager_msg, list);
		list_unlink(&handled_msg->list);

		if (pthread_mutex_unlock(&todo_queue_mutex)) {
			OT_LOG(LOG_ERR, "Failed to lock the mutex");
			continue;
		}

		/* Manager message queue is released */

		/* Exctract messagese part */
		if (com_get_msg_name(handled_msg->msg, &com_msg_name)) {
			OT_LOG(LOG_ERR, "Error with message, discarding");
			free_manager_msg(handled_msg);
			continue;
		}

		if (!handled_msg->proc) {
			OT_LOG(LOG_ERR, "Error with sender details");
			free_manager_msg(handled_msg);
			continue;
		}

		switch (com_msg_name) {
		case COM_MSG_NAME_PROC_STATUS_CHANGE:

			break;

		case COM_MSG_NAME_FD_ERR:

			break;

		case COM_MSG_NAME_CA_INIT_CONTEXT:
			ca_init_context(handled_msg);
			break;

		case COM_MSG_NAME_OPEN_SESSION:
			open_session_msg(handled_msg);
			break;

		case COM_MSG_NAME_INVOKE_CMD:

			break;

		case COM_MSG_NAME_CLOSE_SESSION:

			break;

		case COM_MSG_NAME_CA_FINALIZ_CONTEXT:

			break;

		default:
			/* Just logging an error and message will be ignored */
			OT_LOG(LOG_ERR, "Unknow message, ignore");
			free_manager_msg(handled_msg);
		}
	}

	/* should never reach here */
	OT_LOG(LOG_ERR, "Logic thread is about to exit")
	exit(EXIT_FAILURE); /* TODO: Replace this function with kill tee gracefully */
	return NULL;
}
