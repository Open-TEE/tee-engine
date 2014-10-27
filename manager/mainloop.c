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

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "core_extern_resources.h"
#include "epoll_wrapper.h"
#include "extern_resources.h"
#include "tee_logging.h"

/* Maximum epoll events */
#define MAX_CURR_EVENTS 5

/* TODO: Opentee should switch to use more sophisticated hashtable implementation */
#define ESTIMATE_COUNT_OF_CAS 50
#define ESTIMATE_COUNT_OF_TAS 50

/* These are for tasks received from the caller going to the logic thread */
struct manager_msg todo_queue;

/* These are for tasks that are complete and need to send out */
struct manager_msg done_queue;

/* Socket need to be closed by IO thread */
struct sock_to_close socks_to_close;

/* Client connections */
HASHTABLE clientApps;

/* Loaded TAs (ready accept open sessions) */
HASHTABLE trustedApps;

pthread_mutex_t CA_table_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t TA_table_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t todo_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t done_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t socks_to_close_mutex = PTHREAD_MUTEX_INITIALIZER;

/* IO thead "signaling": wake up logic thread */
pthread_cond_t todo_queue_cond = PTHREAD_COND_INITIALIZER;

/* Launcher process fd */
int launcher_fd;

/* Done queue have something in */
int event_done_queue_fd;

/* Close queue have something to process */
int event_close_sock;

/* Next session ID */
uint64_t next_sess_id;

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
		OT_LOG(LOG_ERR, "Failed to remove %s : %s", sock_path, strerror(errno));
		return -1;
	}

	*pub_sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (*pub_sockfd == -1) {
		OT_LOG(LOG_ERR, "Create socket %s", strerror(errno));
		return -1;
	}

	memset(&sock_addr, 0, sizeof(struct sockaddr_un));
	strncpy(sock_addr.sun_path, sock_path, sizeof(sock_addr.sun_path) - 1);
	sock_addr.sun_family = AF_UNIX;

	if (bind(*pub_sockfd, (struct sockaddr *) &sock_addr, sizeof(struct sockaddr_un)) == -1) {
		OT_LOG(LOG_ERR, "Error %s", strerror(errno));
		return -1;
	}

	if (listen(*pub_sockfd, SOMAXCONN) == -1) {
		OT_LOG(LOG_ERR, "Listen socket %s", strerror(errno));
		return -1;
	}

	return 0;
}

static void manager_check_signal()
{
	/* Placeholder */
	sig_atomic_t cpy_sig_vec = sig_vector;
	reset_signal_self_pipe();

	cpy_sig_vec = cpy_sig_vec; /* Suppress compiler warning */
}

static int init_extern_res(int launcher_proc_fd)
{
	trustedApps = NULL;
	clientApps = NULL;

	/* Linked lists */
	INIT_LIST(&todo_queue.list);
	INIT_LIST(&done_queue.list);
	INIT_LIST(&socks_to_close.list);

	/* CA and TA hashtables */
	h_table_create(&clientApps, ESTIMATE_COUNT_OF_CAS);
	h_table_create(&trustedApps, ESTIMATE_COUNT_OF_TAS);
	if (!clientApps || !trustedApps) {
		OT_LOG(LOG_ERR, "Failed to init clientApps or trustedApps table")
		goto err_1;
	}

	/* Launcher fd */
	launcher_fd = launcher_proc_fd;

	/* First session id is zero */
	next_sess_id = 0;

	/* Done queue event is used in semaphore style */
	event_done_queue_fd = eventfd(0, EFD_SEMAPHORE);
	if (event_done_queue_fd) {
		OT_LOG(LOG_ERR, "Failed to init event_done_queue_fd: %s", strerror(errno));
		goto err_1;
	}

	/* Close socket is only zeroed */
	event_close_sock = eventfd(0, 0);
	if (event_close_sock) {
		OT_LOG(LOG_ERR, "Failed to init event_close_sock: %s", strerror(errno));
		goto err_2;
	}

	return 0;

err_2:
	close(event_done_queue_fd);
err_1:
	h_table_free(clientApps);
	h_table_free(trustedApps);
	return 1;
}

int lib_main_loop(int sockpair_fd)
{
	int clientfd, public_sockfd, i;
	int event_count;
	struct epoll_event cur_events[MAX_CURR_EVENTS];
	char errbuf[MAX_ERR_STRING];

	if (init_extern_res(sockpair_fd))
		return -1; /* err msg logged */

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
				manager_check_signal();
			} else {
				strerror_r(errno, errbuf, MAX_ERR_STRING);
				OT_LOG(LOG_ERR, "Failed return from epoll_wait : %s", errbuf);
			}

			/* In both cases continue, and hope the error clears itself */
			continue;
		}

		for (i = 0; i < event_count; i++) {
			OT_LOG(LOG_ERR, "Spinning in the inner foor loop");

			if (cur_events[i].data.fd == public_sockfd) {
				/* the listen socket has received a connection attempt */
				clientfd = accept(public_sockfd, NULL, NULL);
				if (clientfd == -1) {
					strerror_r(errno, errbuf, MAX_ERR_STRING);
					OT_LOG(LOG_ERR, "Failed to accept child : %s", errbuf);
					/* hope the problem will clear for next connection */
					continue;
				}

				/* Create a dummy process entry to monitor the new client and
				 * just listen for future communications from this socket
				 * If there is already data on the socket, we will be notified
				 * immediatly once we return to epoll_wait() and we can handle
				 * it correctly
				 *
				if (create_uninitialized_client_proc(&new_client, clientfd))
					return -1;

				if (epoll_reg_data(clientfd, EPOLLIN, (void *)new_client))
					return -1;
					*/
			} else {
				//pm_handle_connection(cur_events[i].events, cur_events[i].data.ptr);
			}
		}
	}
}
