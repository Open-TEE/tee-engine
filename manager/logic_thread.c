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

#include "com_protocol.h"
#include "extern_resources.h"
#include "io_thread.h"
#include "tee_list.h"
#include "tee_logging.h"
#include "logic_thread.h"

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

		switch (com_msg_name) {
		case COM_MSG_NAME_PROC_STATUS_CHANGE:

			break;

		case COM_MSG_NAME_FD_ERR:

			break;

		case COM_MSG_NAME_CA_INIT_CONTEXT:

			break;

		case COM_MSG_NAME_OPEN_SESSION:

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
