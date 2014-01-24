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

#include <syslog.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "ta_process.h"
#include "dynamic_loader.h"
#include "epoll_wrapper.h"
#include "utils.h"
#include "tee_list.h"

/* we have 2 threads to synchronize so we can achieve this with static condition and statix mutex */
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;

/* Use eventfd to notify the io_thread that the TA thread has finished processing a task */
static int event_fd;

/*!
 * \brief The task_desc struct
 * This keeps the task desciptor of an operation that has been requested from userspace
 */
struct task_desc {
	struct list_head list;
	struct inter_operation inter_op;
	TEE_Param params[4];
};

// These are for tasks received from the caller going to the TA
struct task_desc tasks_todo;

// These are for tasks that are complete and are being returned to the caller
struct task_desc tasks_done;

/*!
 * \brief notify_failure
 * Notify the manager process that the TA has not initialized correctly so it can perform
 * house keeping
 * \param sockfd The socket that is connected to the manager
 */
static void notify_failure_exit(int sockfd)
{
	/* TODO write to the manager and tell them of the failure to setup the TA process
	 * correctly
	 */
	exit(1);
}

/*!
 * \brief receive_from_manager
 * This function receives a command from the manager process.  It will be of the form
 * open session, invoke command etc.  This function then acts like a producer, in that it
 * creates a task list for the TA thread to work on
 * \param man_sockfd The socket connection to the manager
 */
static void receive_from_manager(int man_sockfd)
{
	int ret;
	char errbuf[MAX_ERR_STRING];
	struct task_desc *task = NULL;
	struct inter_operation i_op;

	// read the operation request from the caller
	if (read(man_sockfd, &i_op, sizeof(struct inter_operation)) !=
	    sizeof(struct inter_operation)) {
		strerror_r(errno, errbuf, MAX_ERR_STRING);
		syslog(LOG_ERR, "Failed read socket : %s\n", errbuf);
		return;
	}

	// create a task for the TA
	task = calloc(1, sizeof(struct task_desc));
	if (task == NULL) {
		syslog(LOG_ERR, "NO MEMORY AVAILABLE\n");
		notify_failure_exit(man_sockfd);
	}

	// generate a TA friendly version of any shared memory
	if (intermediate_to_internal_params(&i_op, task->params) != 0)
		goto error_end;

	ret = pthread_mutex_lock(&mutex);
	if (ret != 0) {
		strerror_r(errno, errbuf, MAX_ERR_STRING);
		syslog(LOG_ERR, "Failed to lock the mutex : %s\n", errbuf);
		goto error_end;
	}

	// enqueue the task in our todo list
	list_add_before(&task->list, &tasks_todo.list);

	ret = pthread_mutex_lock(&mutex);
	if (ret != 0) {
		strerror_r(errno, errbuf, MAX_ERR_STRING);
		syslog(LOG_ERR, "Failed to unlock the mutex : %s\n", errbuf);
		goto error_end2;
	}

	// Inform the TA thread that we have a task to be completed
	ret = pthread_cond_signal(&condition);
	if (ret != 0) {
		strerror_r(errno, errbuf, MAX_ERR_STRING);
		syslog(LOG_ERR, "Failed signal the we have data to consume : %s\n", errbuf);
		goto error_end2;
	}

	return;

error_end2:
	// remove the task from the list on error
	list_unlink(&task->list);
error_end:
	free(task);
	return;
}

/*!
 * \brief reply_to_manager
 * Notify the manager that we have completed an action
 * \param man_sockfd The socket connection to the manager
 */
static void reply_to_manager(int man_sockfd)
{

}

/*!
 * \brief ta_internal_api_thread
 * this thread handles all of the functionality that is part of the actual TA.  This is the
 * true core of the TA process and is where the library functionality of the TA that is laded from
 * the libry is executed
 */
static void *ta_internal_api_thread(void *arg)
{
	const uint64_t event = 1;
	char errbuf[MAX_ERR_STRING];
	int ret;

	arg = arg;

	for (;;) {
		ret = pthread_mutex_lock(&mutex);
		if (ret != 0) {
			strerror_r(errno, errbuf, MAX_ERR_STRING);
			syslog(LOG_ERR, "Failed to lock the mutex : %s\n", errbuf);
			continue;
		}

		// Wait for a task to become available
		while (list_is_empty(&tasks_todo.list)) {
			ret = pthread_cond_wait(&condition, &mutex);
			if (ret != 0) {
				strerror_r(errno, errbuf, MAX_ERR_STRING);
				syslog(LOG_ERR, "Failed to wait for condition : %s\n", errbuf);
				continue;
			}
		}

		// TODO Dequeue 1 task to work on it

		// free the lock so more tasks can be added
		ret = pthread_mutex_lock(&mutex);
		if (ret != 0) {
			strerror_r(errno, errbuf, MAX_ERR_STRING);
			syslog(LOG_ERR, "Failed to unlock the mutex : %s\n", errbuf);
			continue;
		}

		// TODO DO THE WORK ON THE ONE TASK, then take the lock again to write to the
		// output queue

		// notify the I/O thread that we are finished and
		if (write(event_fd, &event, sizeof(uint64_t)) == -1) {
			strerror_r(errno, errbuf, MAX_ERR_STRING);
			syslog(LOG_ERR, "Failed to notify the io thread : %s\n", errbuf);
		}
	}

	/* should never reach here */
	return NULL;
}

int ta_process_loop(const char *lib_path, int man_sockfd)
{
	int ret;
	struct ta_interface *interface = NULL;
	pthread_t ta_thread;
	pthread_attr_t attr;
	char errbuf[MAX_ERR_STRING];
	struct epoll_event cur_events[MAX_CURR_EVENTS];
	int event_count;
	int i;

	INIT_LIST(&tasks_todo.list);
	INIT_LIST(&tasks_done.list);

	ret = load_ta(lib_path, &interface);
	if (ret != TEE_SUCCESS || interface == NULL) {
		syslog(LOG_ERR, "Failed to load the TA");
		notify_failure_exit(man_sockfd);
	}

	ret = interface->create();
	if (ret) {
		syslog(LOG_ERR, "Failed to CreateEntryPoint 0x%x", ret);
		notify_failure_exit(man_sockfd);
	}

	/* create an eventfd, that will allow the writer to increment the count by 1
	 * for each new event, and the reader to decrement by 1 each time, this will allow the
	 * reader to be notified for each new event, as opposed to being notified just once that
	 * there are "event(s)" pending
	 */
	event_fd = eventfd(0, EFD_SEMAPHORE);

	if (init_epoll())
		notify_failure_exit(man_sockfd);

	/* listen to inbound connections from the manager */
	if (epoll_reg_fd(man_sockfd, EPOLLIN))
		notify_failure_exit(man_sockfd);

	/* listen for communications from the TA thread process */
	if (epoll_reg_fd(event_fd, EPOLLIN))
		notify_failure_exit(man_sockfd);

	ret = pthread_attr_init(&attr);
	if (ret) {
		syslog(LOG_ERR, "Failed to create attr for thread in %s : %s\n",
		       lib_path, strerror(errno));
		notify_failure_exit(man_sockfd);
	}

	ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (ret) {
		syslog(LOG_ERR, "Failed set DETACHED for %s : %s\n", lib_path, strerror(errno));
		notify_failure_exit(man_sockfd);
	}

	ret = pthread_create(&ta_thread, &attr, ta_internal_api_thread, NULL);
	if (ret) {
		syslog(LOG_ERR, "Failed launch thread for %s : %s\n", lib_path, strerror(errno));
		notify_failure_exit(man_sockfd);
	}

	/* Enter into the main part of this io_thread */
	for (;;) {
		event_count = wrap_epoll_wait(cur_events, MAX_CURR_EVENTS);
		if (event_count == -1) {
			if (errno != EINTR) {
				strerror_r(errno, errbuf, MAX_ERR_STRING);
				syslog(LOG_ERR, "Failed return from epoll_wait : %s\n", errbuf);
			}

			/* In both cases continue, and hope the error clears itself */
			continue;
		}

		for (i = 0; i < event_count; i++) {
			if (cur_events[i].data.fd == man_sockfd) {
				syslog(LOG_DEBUG, "Received task from the manager\n");
				receive_from_manager(man_sockfd);
			} else if (cur_events[i].data.fd == event_fd) {
				syslog(LOG_DEBUG, "Task finished, inform manager\n");
				reply_to_manager(man_sockfd);
			} else {
				syslog(LOG_ERR, "unknown event source:%d\n", cur_events[i].data.fd);
			}
		}
	}

	/* Should never reach here */
	return -1;
}
