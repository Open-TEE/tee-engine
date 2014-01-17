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

#include <stdlib.h>
#include <syslog.h>
#include <pthread.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "process_manager.h"
#include "epoll_wrapper.h"

enum proc_status {
	Uninitialized,
	Initialized,
	Disconnected,
};

enum proc_type {
	Client,
	TrustedApp,
};

struct __proc {
	pthread_mutex_t mutex;
	enum proc_status status;
	int sockfd;
	enum proc_type p_type;
};

static void session_manager(proc_t ptr)
{
	int bytes_in;
	int available;
	char *buf = NULL;

	/* We have revceived an input event from a client so we must parse the message
	 * and dispatch it to the correct TA.
	 */
	ioctl(ptr->sockfd, FIONREAD, &available);
	buf = (char *)malloc(available);
	if (buf == NULL) {
		syslog(LOG_ERR, "Appear to have no memory\n");
		return;
	}

	bytes_in = read(ptr->sockfd, buf, available);
	syslog(LOG_ERR, "Read %d bytes, from %d : %s\n", bytes_in, available, buf);
	syslog(LOG_ERR, "the socket fd is %d\n", ptr->sockfd);
}

int create_uninitialized_client_proc(proc_t *proc, int sockfd)
{
	*proc = (struct __proc *)malloc(sizeof(struct __proc));
	if (*proc == NULL) {
		syslog(LOG_ERR, "Out of memory");
		return -1;
	}

	if (pthread_mutex_init(&((*proc)->mutex), NULL)) {
		syslog(LOG_ERR, "Failed to create mutex: %d", errno);
		free(*proc);
		return -1;
	}

	(*proc)->status = Uninitialized;
	(*proc)->sockfd = sockfd;
	(*proc)->p_type = Client;

	syslog(LOG_ERR, "Initialized client proc\n");
	return 0;
}

void pm_handle_connection(uint32_t events, void *proc_ptr)
{
	proc_t ptr = (proc_t)proc_ptr;

	if (events & (EPOLLHUP | EPOLLERR)) {
		/* The remote end has hung up or is in error so remove the socket from the
		 * epoll listener and explicitedly close this end of the socket
		 */
		epoll_unreg(ptr->sockfd);
		if (close(ptr->sockfd))
			syslog(LOG_ERR, "Could not close the socket: %d", errno);

	} else if (events & EPOLLIN) {
		/* We have revceived an input event from a client so we must determine
		 * the session context, if one exists, and pass the message to teh other end of that
		 * session
		 */
		session_manager(ptr);
	}
}
