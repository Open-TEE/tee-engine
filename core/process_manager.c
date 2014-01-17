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

static void handle_client_conn(uint32_t events, proc_t ptr)
{

}

static void handle_trusted_conn(uint32_t events, proc_t ptr)
{

}

int create_uninitialized_client_proc(proc_t *proc, int sockfd)
{
	*proc = (struct __proc *)malloc(sizeof(struct __proc));
	if (*proc == NULL) {
		syslog(LOG_ERR, "Out of memory");
		return -1;
	}

	if (pthread_mutex_init((*proc)->mutex, NULL)) {
		syslog(LOG_ERR, "Failed to create mutex: %d", errno);
		free(*proc);
		return -1;
	}

	(*proc)->status = Uninitialized;
	(*proc)->sockfd = sockfd;
	(*proc)->p_type = Client;

	return 0;
}

void pm_handle_connection(uint32_t events, void *proc_ptr)
{
	proc_t ptr = (proc_t)proc_ptr;

	if (ptr->p_type == Client)
		handle_client_conn(events, ptr);
	else if (ptr->p_type == TrustedApp)
		handle_trusted_conn(events, ptr);
	else
		syslog(LOG_ERR, "Unknown connection type: %d", ptr->p_type);

}
