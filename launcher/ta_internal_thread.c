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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "com_protocol.h"
#include "dynamic_loader.h"
#include "ta_extern_resources.h"
#include "ta_internal_thread.h"
#include "tee_data_types.h"
#include "ta_io_thread.h"
#include "tee_list.h"
#include "tee_logging.h"

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

static void open_session(struct ta_task *in_task)
{
	struct com_msg_open_session *open_msg = in_task->msg;

	if (open_msg->msg_hdr.msg_name != COM_MSG_NAME_OPEN_SESSION ||
	    open_msg->msg_hdr.msg_type != COM_TYPE_QUERY) {
		OT_LOG(LOG_ERR, "Invalid message, ignore");
		free_task(in_task);
		return;
	}

	/* Do the task */
	open_msg->return_code_open_session = interface->open_session(0, 0, NULL);

	open_msg->return_origin = TEE_ORIGIN_TRUSTED_APP;
	open_msg->msg_hdr.msg_type = COM_TYPE_RESPONSE;

	add_msg_done_queue_and_notify(in_task);
}

static void invoke_cmd(struct ta_task *in_task)
{
	struct com_msg_invoke_cmd *invoke_msg = in_task->msg;

	if (invoke_msg->msg_hdr.msg_name != COM_MSG_NAME_INVOKE_CMD ||
	    invoke_msg->msg_hdr.msg_type != COM_TYPE_QUERY) {
		OT_LOG(LOG_ERR, "Invalid message, ignore");
		free_task(in_task);
		return;
	}

	/* Do the task */
	invoke_msg->return_code = interface->invoke_cmd(NULL, invoke_msg->cmd_id, 0, 0);

	invoke_msg->return_origin = TEE_ORIGIN_TRUSTED_APP;
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

	interface->close_session(NULL);

	if (close_msg->should_ta_destroy) {
		interface->destroy();
		exit(EXIT_SUCCESS);
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
		exit(EXIT_FAILURE);
	}

	open_ta_task->msg = open_msg;
	open_ta_task->msg_len = sizeof(struct com_msg_open_session);

	open_session(open_ta_task);
}

void *ta_internal_thread(void *arg)
{
	int ret;
	struct ta_task *task;
	uint8_t com_msg_name;

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
	exit(EXIT_FAILURE);
	return NULL;
}
