/*****************************************************************************
** Copyright (C) 2014 Brian McGillion.                                      **
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
#include <stdlib.h>
#include <sys/eventfd.h>

#include "com_protocol.h"
#include "core_extern_resources.h"
#include "dynamic_loader.h"
#include "ta_extern_resources.h"
#include "ta_process.h"
#include "tee_logging.h"

/* we have 2 threads to synchronize so we can achieve this with static condition and statix mutex */
pthread_mutex_t todo_list_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t done_list_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t condition = PTHREAD_COND_INITIALIZER;

/* Interface TA funcitons */
struct ta_interface *interface;

/* Use eventfd to notify the io_thread that the TA thread has finished processing a task */
int event_fd;

/* These are for tasks received from the caller going to the TA */
struct ta_task tasks_todo;

/* These are for tasks that are complete and are being returned to the caller */
struct ta_task tasks_done;

int ta_process_loop(int man_sockfd, struct com_msg_open_session *open_msg)
{
	TEEC_Result ret;
	struct ta_interface *interface;
	man_sockfd = man_sockfd;
	open_msg = open_msg;

	/* Load TA to this process */
	ret = load_ta(open_msg->ta_so_name, &interface);
	if (ret != TEE_SUCCESS || interface == NULL) {
		OT_LOG(LOG_ERR, "Failed to load the TA");
		exit(EXIT_FAILURE);
	}

	/* create an eventfd, that will allow the writer to increment the count by 1
	 * for each new event, and the reader to decrement by 1 each time, this will allow the
	 * reader to be notified for each new event, as opposed to being notified just once that
	 * there are "event(s)" pending*/
	event_fd = eventfd(0, EFD_SEMAPHORE);
	if (event_fd == -1) {
		OT_LOG(LOG_ERR, "Failed to initialize eventfd");
		exit(EXIT_FAILURE);
	}

	/* Initializations of TODO and DONE queues*/
	INIT_LIST(&tasks_todo.list);
	INIT_LIST(&tasks_done.list);

	/* Should never reach here */
	exit(EXIT_FAILURE);
}
