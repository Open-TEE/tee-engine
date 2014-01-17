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
#include <errno.h>

#include "subprocess.h"
#include "context_child.h"
#include "epoll_wrapper.h"
#include "process_manager.h"

#define MAX_CURR_EVENTS 5
#define MAX_ERR_STRING 100

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
	int clientfd, public_sockfd, i;
	int event_count;
	struct epoll_event cur_events[MAX_CURR_EVENTS];
	char errbuf[MAX_ERR_STRING];
	proc_t new_client;

	if (init_epoll())
		return -1;

	if (init_sock(&public_sockfd))
		return -1;

	/* listen to inbound connections from userspace clients */
	if (epoll_reg_fd(public_sockfd, EPOLLIN))
		return -1;

	/* listen for communications from the launcher process */
	if (epoll_reg_fd(sockpair_fd, EPOLLIN))
		return -1;

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
			syslog(LOG_ERR, "Spinning in the inner foor loop");

			if (cur_events[i].data.fd == public_sockfd) {
				/* the listen socket has received a connection attempt */
				clientfd = accept(public_sockfd, NULL, NULL);
				if (clientfd == -1) {
					strerror_r(errno, errbuf, MAX_ERR_STRING);
					syslog(LOG_ERR, "Failed to accept child : %s", errbuf);
					/* hope the problem will clear for next connection */
					continue;
				}

				/* Create a dummy process entry to monitor the new client and
				 * just listen for future communications from this socket
				 * If there is already data on the socket, we will be notified
				 * immediatly once we return to epoll_wait() and we can handle
				 * it correctly
				 */
				if (create_uninitialized_client_proc(&new_client, clientfd))
					return -1;

				if (epoll_reg_data(clientfd, EPOLLIN, (void *)new_client))
					return -1;
			} else {
				pm_handle_connection(cur_events[i].events, cur_events[i].data.ptr);
			}
		}
	}
}
