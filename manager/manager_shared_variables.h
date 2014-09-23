/*****************************************************************************
** Copyright (C) 2014 Intel Corporation.                                    **
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

//#ifdef MAN_SHARED_VARS_DEC
//#undef __MANAGER_SHARED_VARIABLES_H__
//#endif

#ifndef __MANAGER_SHARED_VARIABLES_H__
#define __MANAGER_SHARED_VARIABLES_H__

#include <stdint.h>
#include <sys/types.h>

#include "h_table.h"
#include "tee_list.h"
#include "general_data_types.h"
#include "epoll_wrapper.h"

extern HASHTABLE clientApps;
extern HASHTABLE trustedApps;

extern pthread_mutex_t CA_table_mutex;
extern pthread_mutex_t TA_table_mutex;

extern pthread_mutex_t todo_queue_mutex;
extern pthread_cond_t todo_queue_cond;

extern pthread_mutex_t done_queue_mutex;
extern pthread_cond_t done_queue_cond;

extern int launcher_fd;
extern uint64_t next_proc_id;
extern int event_fd;
extern void manager_check_signals(struct epoll_event *event);

enum proc_status {
	Uninitialized,
	Initialized,
	Disconnected,
	Panicked,
};

enum proc_type {
	ClientApp,
	TrustedApp,
	sessionLink
};

enum session_status {
	session_initialized,
	session_active,
	session_closed,
	session_panicked,
};

struct __proc {
	enum proc_type p_type;

	union {
		struct {
			enum session_status status;
			int session_id;
			int sockfd;
			void *open_session_data;
			int open_session_data_len;
			struct __proc *to;
			struct __proc *owner;
		} sesLink;

		struct {
			int sockfd;
			pid_t pid;
			enum proc_status status;
			TEE_UUID ta_uuid;
			HASHTABLE links; /* Hashtable */
		} process;

	} content;
};

extern struct manager_msg todo_queue;
extern struct manager_msg done_queue;

struct manager_msg {
	struct list_head list;
	void *msg;
	int msg_len;
	struct __proc *proc; /* Act as "sender/receiver" detail */
};

//#ifdef DEFINE_VARIABLES
//#define MAN_SHARED_VARS_DEC
//#endif /* DEFINE_VARIABLES */

#endif /* __MANAGER_SHARED_VARIABLES_H__ */
