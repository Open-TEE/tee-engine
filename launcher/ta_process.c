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
#include "ta_exit_states.h"
#include "ta_ctl_resources.h"
#include "ta_internal_thread.h"
#include "ta_io_thread.h"
#include "ta_process.h"
#include "ta_signal_handler.h"
#include "tee_logging.h"

/* we have 2 threads to synchronize so we can achieve this with static condition and statix mutex */
pthread_mutex_t todo_list_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t done_list_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t condition = PTHREAD_COND_INITIALIZER;

/* Blocking internal thread while waiting response message */
pthread_mutex_t block_internal_thread_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t block_condition = PTHREAD_COND_INITIALIZER;

/* Synchronize executed_operation_id variable accessing */
pthread_mutex_t executed_operation_id_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Logic thread update to here what is executed operation ID */
uint64_t executed_operation_id;

/* Not creating own message queue for response messages, because only one message can be
 * at time. So only one response message can be received */
void *response_msg;

/* Interface TA funcitons */
struct ta_interface *interface;

/* Use eventfd to notify the io_thread that the TA thread has finished processing a task */
int event_fd;

/* Graceful is an extra and in normal operation this is obsolite. This is for debuging.
 * Graceful termination is working after create entry point call! If TA is failing to set up
 * framework, resources is not released by this process. */
#ifdef GRACEFUL_TERMINATION
	/* Logic thread will signal throug termination_fd to io thread that destroy entry point has
	 * been executed and this process need to be clean up */
	int termination_fd;

	/* Variable is storing exit value. Logic thread is deciding exit value and this is
	 * used by IO thread when it is cleaned up all resources */
	int graceful_exit_value;
#endif

/* These are for tasks received from the caller going to the TA */
struct ta_task tasks_todo;

/* These are for tasks that are complete and are being returned to the caller */
struct ta_task tasks_done;

/* Interal API cancel functionality */
bool cancellation_mask;
bool cancellation_flag;

/* Maximum epoll events */
#define MAX_CURR_EVENTS 5

#ifdef GRACEFUL_TERMINATION
static void clear_queues()
{
	struct list_head *pos, *la;
	struct ta_task *queue_task;

	/* Mutex not needed, bevause logic thread is ended its execution */

	/* Done Queue */
	if (!list_is_empty(&tasks_done.list)) {

		LIST_FOR_EACH_SAFE(pos, la, &tasks_done.list) {
			queue_task = LIST_ENTRY(pos, struct ta_task, list);
			list_unlink(&queue_task->list);
			free_task(queue_task);
		}
	}

	/* Todo queue */
	if (!list_is_empty(&tasks_todo.list)) {

		LIST_FOR_EACH_SAFE(pos, la, &tasks_todo.list) {
			queue_task = LIST_ENTRY(pos, struct ta_task, list);
			list_unlink(&queue_task->list);
			free_task(queue_task);
		}
	}
}
#endif

int ta_process_loop(void *arg)
{
	int ret;
	pthread_t ta_logic_thread;
	pthread_attr_t attr;
	struct epoll_event cur_events[MAX_CURR_EVENTS];
	int event_count, i;
	char proc_name[MAX_PR_NAME] = {0}; /* For now */
	sigset_t sig_empty_set;
	char *path = NULL;
	struct core_control *ctl_params = ((struct ta_loop_arg *)arg)->ctl_params;
	struct com_msg_open_session *open_msg = ((struct ta_loop_arg *)arg)->recv_open_msg;
	int man_sockfd = ((struct ta_loop_arg *)arg)->com_sock;

	/* Launchers manger socket is not needed in TA */
	close(ctl_params->comm_sock_fd);
	prctl(PR_SET_PDEATHSIG, SIGKILL);
	closelog();

	/* Set new ta process name */
	strncpy(proc_name, open_msg->ta_so_name, ctl_params->argv0_len);
	prctl(PR_SET_NAME, (unsigned long)proc_name);
	strncpy(ctl_params->argv0, proc_name, ctl_params->argv0_len);

	openlog(proc_name, 0, LOG_USER);

	if (asprintf(&path, "%s/%s", ctl_params->opentee_conf->ta_dir_path,
		     open_msg->ta_so_name) == -1) {
		OT_LOG(LOG_ERR, "out of memory");
		exit(TA_EXIT_LAUNCH_FAILED);
	}

	/* Load TA to this process */
	ret = load_ta(path, &interface);
	if (ret != TEE_SUCCESS || interface == NULL) {
		OT_LOG(LOG_ERR, "Failed to load the TA");
		exit(TA_EXIT_LAUNCH_FAILED);
	}

	/* Finished with the library path name so clean it up */
	free(path);

	/* Note: All signal are blocked. Prepare allow set when we can accept signals */
	if (sigemptyset(&sig_empty_set)) {
		OT_LOG(LOG_ERR, "Sigempty set failed: %s", strerror(errno));
		exit(TA_EXIT_LAUNCH_FAILED);
	}

	/* create an eventfd, that will allow the writer to increment the count by 1
	 * for each new event, and the reader to decrement by 1 each time, this will allow the
	 * reader to be notified for each new event, as opposed to being notified just once that
	 * there are "event(s)" pending*/
	event_fd = eventfd(0, EFD_SEMAPHORE);
	if (event_fd == -1) {
		OT_LOG(LOG_ERR, "Failed to initialize eventfd");
		exit(TA_EXIT_LAUNCH_FAILED);
	}
#ifdef GRACEFUL_TERMINATION
	termination_fd = eventfd(0, 0);
	if (termination_fd == -1) {
		OT_LOG(LOG_ERR, "Failed to initialize termination_fd");
		exit(TA_EXIT_LAUNCH_FAILED);
	}
#endif
	/* Initializations of TODO and DONE queues*/
	INIT_LIST(&tasks_todo.list);
	INIT_LIST(&tasks_done.list);

	/* Note: Launcher has inited epoll.
	 * Listen to inbound connections from the manager */
	if (epoll_reg_fd(man_sockfd, EPOLLIN))
		exit(TA_EXIT_LAUNCH_FAILED);

	/* listen for communications from the TA thread process */
	if (epoll_reg_fd(event_fd, EPOLLIN))
		exit(TA_EXIT_LAUNCH_FAILED);

#ifdef GRACEFUL_TERMINATION
	/* Logic and IO thread communication about termination */
	if (epoll_reg_fd(termination_fd, EPOLLIN))
		exit(TA_EXIT_LAUNCH_FAILED);
#endif

	/* Init worker thread */
	ret = pthread_attr_init(&attr);
	if (ret) {
		OT_LOG(LOG_ERR, "Failed to create attr for thread: %s", strerror(errno));
		exit(TA_EXIT_LAUNCH_FAILED);
	}

	/* TODO: Should we reserver space for thread stack? */

	ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (ret) {
		OT_LOG(LOG_ERR, "Failed set DETACHED: %s", strerror(errno));
		exit(TA_EXIT_LAUNCH_FAILED);
	}

	/* limitation: CA can not determ if TA is launched or not, because framework is calling
	 * create entry point and open session function. Those functions return values is mapped
	 * into one return value. */

	/* Launch worker thread and pass open session message as a parameter */
	ret = pthread_create(&ta_logic_thread, &attr, ta_internal_thread, open_msg);
	if (ret) {
		OT_LOG(LOG_ERR, "Failed launch thread: %s", strerror(errno));
		exit(TA_EXIT_FIRST_OPEN_SESS_FAILED);
	}

	pthread_attr_destroy(&attr); /* Not needed any more */

	/* Allow signal delivery */
	if (pthread_sigmask(SIG_SETMASK, &sig_empty_set, NULL)) {
		OT_LOG(LOG_ERR, "failed to allow signals: %s", strerror(errno));
		exit(TA_EXIT_FIRST_OPEN_SESS_FAILED);
	}

	/* Note: Graceful termination is working after this point */

	/* Enter into the main part of this io_thread */
	for (;;) {
		event_count = wrap_epoll_wait(cur_events, MAX_CURR_EVENTS);
		if (event_count == -1) {
			if (errno == EINTR) {
				ta_signal_handler(ctl_params);
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

			} else if (cur_events[i].data.fd == ctl_params->self_pipe_fd) {
				ta_signal_handler(ctl_params);

#ifdef GRACEFUL_TERMINATION
			} else if (cur_events[i].data.fd == termination_fd) {
				goto termination;
#endif
			} else {
				OT_LOG(LOG_ERR, "unknown event source");
			}
		}
	}

	/* Should never reach here */
	exit(TA_EXIT_PANICKED);

#ifdef GRACEFUL_TERMINATION
termination:
	/* Release resources that have been alloced by launcher/core process */
	ctl_params->fn_cleanup_launher();
	ctl_params->fn_cleanup_core();

	/* Remove all messages from queues */
	clear_queues();

	/* Assuming that mutex will be destroyed. If not, this process will be terminated anyway */
	pthread_mutex_destroy(&todo_list_mutex);
	pthread_mutex_destroy(&done_list_mutex);
	pthread_mutex_destroy(&block_internal_thread_mutex);
	pthread_mutex_destroy(&executed_operation_id_mutex);

	/* Conditional variables */
	pthread_cond_destroy(&condition);
	pthread_cond_destroy(&block_condition);

	/* Close FDs */
	close(event_fd);
	close(termination_fd);
	close(man_sockfd);

	/* Close syslog */
	closelog();

	exit(graceful_exit_value);
#endif
}
