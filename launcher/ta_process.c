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

#define MAX_ERR_STRING 255

/* we have 2 threads to synchronize so we can achieve this with static condition and statix mutex */
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;

/* Use eventfd to notify the io_thread that the TA thread has finished processing a task */
static int event_fd;

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

static void receive_from_manager(int man_sockfd)
{

}

static void reply_to_manager()
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
	uint64_t event = 1;
	char errbuf[MAX_ERR_STRING];

	arg = arg;

	if (write(event_fd, &event, sizeof(uint64_t)) == -1) {
		strerror_r(errno, errbuf, MAX_ERR_STRING);
		syslog(LOG_ERR, "Failed to notify the io thread : %s\n", errbuf);
		/* TODO: What should we do here how can we abort ?? */
	}

	/* should never reach here */
	return NULL;
}

int ta_process_loop(const char *lib_path, int man_sockfd)
{
	int ret;
	struct ta_interface *interface;
	pthread_t ta_thread;
	pthread_attr_t attr;
	char errbuf[MAX_ERR_STRING];
	struct epoll_event cur_events[MAX_CURR_EVENTS];
	int event_count;
	int i;

	ret = load_ta(lib_path, &interface);
	if (ret != TEE_SUCCESS) {
		syslog(LOG_ERR, "Failed to load the TA");
		notify_failure_exit(man_sockfd);
	}

	/* TODO should set the process name to the name of the TA UUID ? */

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

	/* listen for communications from the launcher process */
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
				reply_to_manager();
			} else {
				syslog(LOG_ERR, "unknown event source:%d\n", cur_events[i].data.fd);
			}
		}
	}

	/* Should never reach here */
	return -1;
}
