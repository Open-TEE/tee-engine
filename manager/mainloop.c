/*****************************************************************************
** Copyright (C) 2013 Brian McGillion                                       **
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/un.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <sys/eventfd.h>

#include "subprocess.h"
#include "epoll_wrapper.h"
#include "manager_io_thread.h"
#include "tee_list.h"
#include "h_table.h"
#include "manager_shared_variables.h"
#include "manager_logic_thread.h"

#define MAX_CURR_EVENTS 5
static const int MAX_ERR_STRING = 100;

struct manager_msg todo_queue;
struct manager_msg done_queue;

HASHTABLE clientApps;
HASHTABLE trustedApps;

pthread_mutex_t CA_table_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t TA_table_mutex = PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t todo_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t todo_queue_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t done_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t done_queue_cond = PTHREAD_COND_INITIALIZER;

int launcher_fd;
int event_fd;
uint64_t next_proc_id;

/*!
 * \brief init_sock
 * Initialize the daemons main public socket and listen for inbound connections
 * \param pub_sockfd The main socket to which clients connect
 * \return 0 on success -1 otherwise
 */
static int init_sock(int *pub_sockfd)
{
	const char *sock_path = "/tmp/open_tee_sock";
	struct sockaddr_un sock_addr;

	if (remove(sock_path) == -1 && errno != ENOENT) {
		syslog(LOG_ERR, "Failed to remove %s : %s", sock_path, strerror(errno));
		return -1;
	}

	*pub_sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (*pub_sockfd == -1) {
		syslog(LOG_ERR, "Create socket %s", strerror(errno));
		return -1;
	}

	memset(&sock_addr, 0, sizeof(struct sockaddr_un));
	strncpy(sock_addr.sun_path, sock_path, sizeof(sock_addr.sun_path) - 1);
	sock_addr.sun_family = AF_UNIX;

	if (bind(*pub_sockfd, (struct sockaddr *) &sock_addr, sizeof(struct sockaddr_un)) == -1) {
		syslog(LOG_ERR, "Error %s", strerror(errno));
		return -1;
	}

	if (listen(*pub_sockfd, SOMAXCONN) == -1) {
		syslog(LOG_ERR, "Listen socket %s", strerror(errno));
		return -1;
	}

	return 0;
}

int lib_main_loop(sig_status_cb check_signal_status, int sockpair_fd)
{
	int public_sockfd, i;
	int event_count;
	struct epoll_event cur_events[MAX_CURR_EVENTS];
	char errbuf[MAX_ERR_STRING];
	pthread_t logic_thread;
	pthread_attr_t attr;
	int ret;
	sigset_t sig_empty_set;

	if (sigemptyset(&sig_empty_set)) {
		syslog(LOG_ERR, "lib_main_loop: Sigempty set failed\n");
		return -1;
	}

	INIT_LIST(&todo_queue.list);
	INIT_LIST(&done_queue.list);
	h_table_create(&clientApps, 100);
	h_table_create(&trustedApps, 100);
	launcher_fd = sockpair_fd;
	next_proc_id = 0;
	event_fd = eventfd(0, EFD_SEMAPHORE);

	if (event_fd == -1)
		return -1;

	if (!clientApps || !trustedApps)
		return -1;

	if (init_epoll())
		return -1;

	if (init_sock(&public_sockfd))
		return -1;

	/* listen to inbound connections from userspace clients */
	if (epoll_reg_fd(public_sockfd, EPOLLIN))
		return -1;

	/* listen for communications from the launcher process
	if (epoll_reg_fd(sockpair_fd, EPOLLIN))
		return -1;
	*/

	if (epoll_reg_fd(event_fd, EPOLLIN))
		return -1;

	ret = pthread_attr_init(&attr);
	if (ret) {
		syslog(LOG_ERR, "Failed to create attr for thread in : %s\n", strerror(errno));
		return -1;
	}

	ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (ret) {
		syslog(LOG_ERR, "Failed set DETACHED for : %s\n", strerror(errno));
		return -1;
	}

	ret = pthread_create(&logic_thread, &attr, manager_logic_main_thread, NULL);
	if (ret) {
		syslog(LOG_ERR, "Failed launch thread for : %s\n", strerror(errno));
		return -1;
	}

	/* NB everything after this point must be thread safe */
	for (;;) {
		/* Block and wait for a one of the monitored I/Os to become available */
		event_count = wrap_epoll_wait(cur_events, MAX_CURR_EVENTS);
		if (event_count == -1) {
			if (errno == EINTR) {
				/* We have been interrupted so check which of our signals it was
				 * and act on it, though it may have been a SIGCHLD
				 */
				check_signal_status();
			} else {
				strerror_r(errno, errbuf, MAX_ERR_STRING);
				syslog(LOG_ERR, "Failed return from epoll_wait : %s", errbuf);
			}

			/* In both cases continue, and hope the error clears itself */
			continue;
		}

		for (i = 0; i < event_count; i++) {

			if (cur_events[i].data.fd == public_sockfd) {
				handle_public_fd(public_sockfd);

			} else if (cur_events[i].data.fd == event_fd) {
				handle_done_queue();

			} else {
				pm_handle_connection(cur_events[i].events, cur_events[i].data.ptr);
			}
		}
	}

cleanup:
	/* TODO: Add mutex. This is to do, because there is no "shutdown" function. */
	h_table_free(clientApps);
	h_table_free(trustedApps);
}
