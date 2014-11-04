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

#define _GNU_SOURCE

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/prctl.h>
#include <stdio.h>

#include "com_protocol.h"
#include "conf_parser.h"
#include "core_control_resources.h"
#include "dynamic_loader.h"
#include "epoll_wrapper.h"
#include "ta_extern_resources.h"
#include "ta_internal_thread.h"
#include "ta_io_thread.h"
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

/* Maximum epoll events */
#define MAX_CURR_EVENTS 5

int ta_process_loop(struct core_control *control_params, int man_sockfd,
		    struct com_msg_open_session *open_msg)
{
	int ret;
	pthread_t ta_logic_thread;
	pthread_attr_t attr;
	struct epoll_event cur_events[MAX_CURR_EVENTS];
	int event_count, i;
	char proc_name[MAX_PR_NAME]; /* For now */
	sigset_t sig_empty_set;
	char *path = NULL;

	/* Set new ta process name */
	strncpy(proc_name, open_msg->ta_so_name, MAX_PR_NAME);
	prctl(PR_SET_NAME, (unsigned long)proc_name);
	strncpy(control_params->argv0, proc_name, control_params->argv0_len);

	openlog(proc_name, 0, LOG_USER);

	if (asprintf(&path, "%s/%s", control_params->opentee_conf->ta_dir_path,
		     open_msg->ta_so_name) == -1) {
		OT_LOG(LOG_ERR, "out of memory");
		exit(EXIT_FAILURE);
	}

	/* Load TA to this process */
	ret = load_ta(path, &interface);
	if (ret != TEE_SUCCESS || interface == NULL) {
		OT_LOG(LOG_ERR, "Failed to load the TA");
		exit(EXIT_FAILURE);
	}

	/* Finished with the library path name so clean it up */
	free(path);

	/* Note: All signal are blocked. Prepare allow set when we can accept signals */
	if (sigemptyset(&sig_empty_set)) {
		OT_LOG(LOG_ERR, "Sigempty set failed: %s", strerror(errno))
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

	/* Init epoll and register FD/data */
	if (init_epoll())
		exit(EXIT_FAILURE);

	/* listen to inbound connections from the manager */
	if (epoll_reg_fd(man_sockfd, EPOLLIN))
		exit(EXIT_FAILURE);

	/* listen for communications from the TA thread process */
	if (epoll_reg_fd(event_fd, EPOLLIN))
		exit(EXIT_FAILURE);

	/* Signal handling */
	if (epoll_reg_fd(control_params->self_pipe_fd, EPOLLIN))
		exit(EXIT_FAILURE);

	/* Init worker thread */
	ret = pthread_attr_init(&attr);
	if (ret) {
		OT_LOG(LOG_ERR, "Failed to create attr for thread: %s", strerror(errno))
		exit(EXIT_FAILURE);
	}

	/* TODO: Should we reserver space for thread stack? */

	ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (ret) {
		OT_LOG(LOG_ERR, "Failed set DETACHED: %s", strerror(errno))
		exit(EXIT_FAILURE);
	}

	/* Known error: CA can not determ if TA is launched or not, because framework is calling
	 * create entry point and open session function. Those functions return values is mapped
	 * into one return value. */
	if (interface->create() != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TA create entry point failed");
		exit(EXIT_SUCCESS);
	}

	/* Launch worker thread and pass open session message as a parameter */
	ret = pthread_create(&ta_logic_thread, &attr, ta_internal_thread, open_msg);
	if (ret) {
		OT_LOG(LOG_ERR, "Failed launch thread: %s", strerror(errno))
		interface->destroy();
		exit(EXIT_FAILURE);
	}

	pthread_attr_destroy(&attr); /* Not needed any more */

	/* Allow signal delivery */
	if (pthread_sigmask(SIG_SETMASK, &sig_empty_set, NULL)) {
		OT_LOG(LOG_ERR, "failed to allow signals: %s", strerror(errno))
		exit(EXIT_FAILURE);
	}

	/* Enter into the main part of this io_thread */
	for (;;) {
		event_count = wrap_epoll_wait(cur_events, MAX_CURR_EVENTS);
		if (event_count == -1) {
			if (errno == EINTR) {

				continue;
			}

			/* Log error and hope the error clears itself */
			OT_LOG(LOG_ERR, "Failed return from epoll_wait");
			continue;
		}

		for (i = 0; i < event_count; i++) {

			if (cur_events[i].data.fd == man_sockfd) {
				receive_from_manager(&cur_events[i], man_sockfd);

			} else if (cur_events[i].data.fd == event_fd) {
				reply_to_manager(&cur_events[i], man_sockfd);

			} else if (cur_events[i].data.fd == control_params->self_pipe_fd) {

			} else {
				OT_LOG(LOG_ERR, "unknown event source");
			}
		}
	}

	/* Should never reach here */
	exit(EXIT_FAILURE);
}
