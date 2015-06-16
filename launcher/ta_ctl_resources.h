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

#ifndef __TA_CONTROL_PARAMS_H__
#define __TA_CONTROL_PARAMS_H__

#include <pthread.h>
#include <stdbool.h>

#include "tee_list.h"

/* Struct ta_task will be used for communication between thread */
struct ta_task {
	struct list_head list;
	void *msg;
	int msg_len;
};

/* These are for tasks received from the caller going to the TA */
extern struct list_head tasks_in_list;

/* These are for tasks that are complete and are being returned to the caller */
extern struct list_head tasks_out_list;

/* Interface TA funcitons */
extern struct ta_interface *interface;

/* we have 2 threads to synchronize so we can achieve this with static condition and statix mutex */
extern pthread_mutex_t tasks_in_list_mutex;
extern pthread_mutex_t tasks_out_list_mutex;
extern pthread_cond_t condition;

/* Blocking internal thread while waiting response message */
extern pthread_mutex_t block_internal_thread_mutex;
extern pthread_cond_t block_condition;

/* Synchronize executed_operation_id variable accessing */
extern pthread_mutex_t executed_operation_id_mutex;

/* Logic thread update to here what is executed operation ID */
extern uint64_t executed_operation_id;

/* Not creating own message queue for response messages, because only one message can be
 * at time. So only one response message can be received */
extern void *response_msg;

/* Use eventfd to notify the io_thread that the TA thread has finished processing a task */
extern int event_fd;

/* Graceful is an extra and in normal operation this is obsolite. This is for debuging.
 * Graceful termination is working after create entry point call! If TA is failing to set up
 * framework, resources is not released by this process. */
#ifdef GRACEFUL_TERMINATION
	/* Logic thread will signal throug termination_fd to io thread that destroy entry point has
	 * been executed and this process need to be clean up */
	extern int termination_fd;

	/* Variable is storing exit value. Logic thread is deciding exit value and this is
	 * used by IO thread when it is cleaned up all resources */
	extern int graceful_exit_value;
#endif

/* Interal API cancel functionality */
extern bool cancellation_mask;
extern bool cancellation_flag;

#endif /* __TA_CONTROL_PARAMS_H__ */
