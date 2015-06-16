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

#ifndef __EXTERN_RESOURCES_H__
#define __EXTERN_RESOURCES_H__

#include <pthread.h>
#include <stdint.h>

#include "com_protocol.h"
#include "tee_list.h"
#include "tee_shared_data_types.h"

#define WAIT_NO_MSG_OUT		1
#define WAIT_OPEN_SESSION_MSG	2
#define WAIT_INVOKE_MSG		3

/* define an opaque structure to handle the process related information */
typedef struct __proc *proc_t;

/* IO thread will close sockfd */
struct sock_to_close {
	struct list_head list;
	int sockfd;
};

/* Received message is malloced to msg parameter and it lenght will be in msg_len.
 */
struct manager_msg {
	struct list_head list;
	void *msg;
	int msg_len;
	proc_t proc; /* Act as "sender/receiver" detail */
};

struct proc_shm_mem {
	struct list_head list;
	char name[SHM_MEM_NAME_LEN];
	int size;
	int fd;
};

/* These are for tasks received from the caller going to the logic thread */
extern struct list_head inbound_queue_list;

/* These are for tasks that are complete and need to send out */
extern struct list_head outbound_queue_list;

/* Socket need to be closed by IO thread */
extern struct list_head socks_to_close_list;

/* Client connections */
extern struct list_head ca_list;

/* Loaded TAs (ready accept open sessions) */
extern struct list_head ta_list;

/* Data structures mutex */
extern pthread_mutex_t CA_table_mutex;
extern pthread_mutex_t TA_table_mutex;
extern pthread_mutex_t inbound_queue_mutex;
extern pthread_mutex_t outbound_queue_mutex;
extern pthread_mutex_t socks_to_close_mutex;

/* IO thead "signaling": wake up logic thread */
extern pthread_cond_t inbound_queue_cond;

/* Launcher process fd */
extern int launcher_fd;

/* Done queue have something in */
extern int event_out_queue_fd;

/* Close queue have something to process */
extern int event_close_sock;

/* Note: Do not assign enumerator values. Let compiler do that.
 * If manual assigment needed, do it after XXXX_last-element */

/* Different proc type will be handeled in different way */
enum proc_type {
	proc_t_CA = 1,
	proc_t_TA,
	proc_t_session,
	proc_t_last, /* Used for "looping" through enumerator */
};

/* Note: Might not be complite */
enum proc_status {
	proc_uninitialized = 1,
	proc_initialized,
	proc_active,
	proc_disconnected,
	proc_panicked,
	proc_undefined,
	proc_status_last, /* Used for "looping" through enumerator */
};

/* Note: Might not be complite */
enum session_status {
	sess_initialized = 1,
	sess_active,
	sess_closed,
	sess_panicked,
	sess_undefined,
	sess_status_last, /* Used for "looping" through enumerator */
};

/* Process name is a bit missleading.
 * Process: ClientApp or TrustedApp
 * Sessionlink: Links CA or TA session to another session.
 * Point: Sessionlink is representing opened session between applicatons */
struct sesLink {
	enum proc_type p_type;
	struct list_head list;
	proc_t owner;
	struct sesLink *to;
	uintptr_t sess_ctx;
	uint64_t session_id;
	int waiting_response_msg;
	enum session_status status;
};

struct __proc {
	int sockfd;
	enum proc_type p_type;
	struct list_head list;
	TEE_UUID ta_uuid;
	struct sesLink links;
	struct proc_shm_mem shm_mem;
	pid_t pid;
	enum proc_status status;
};

#endif /* __EXTERN_RESOURCES_H__ */
