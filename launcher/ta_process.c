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
#include <sys/prctl.h>
#include <stdlib.h>
#include <dlfcn.h>

#include "ta_process.h"
#include "dynamic_loader.h"
#include "epoll_wrapper.h"
#include "utils.h"
#include "tee_list.h"
#include "socket_help.h"
#include "com_protocol.h"
#include "subprocess.h"

/* we have 2 threads to synchronize so we can achieve this with static condition and statix mutex */
static pthread_mutex_t todo_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t done_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;

static const int EXIT_OUT_OF_MEMORY = 22;

/* Interface TA funcitons */
static struct ta_interface *interface;

/* Use eventfd to notify the io_thread that the TA thread has finished processing a task */
static int event_fd;
static int exit_event_fd;

struct ta_task {
	struct list_head list;
	void *msg;
	int msg_len;
};

/*!
 * \brief The task_desc struct
 * This keeps the task desciptor of an operation that has been requested from userspace
 */
struct ta_task_desc {
	struct list_head list;
	struct inter_operation inter_op;
	TEE_Param params[4];
};

// These are for tasks received from the caller going to the TA
struct ta_task_desc tasks_todo;

// These are for tasks that are complete and are being returned to the caller
struct ta_task_desc tasks_done;

static free_task(struct ta_task *released_task)
{
	free(released_task->msg);
	free(released_task);
}

static void send_msg(int to_fd, void *msg, int msg_len)
{
	int send_bytes;

	if (msg_len == 0)
		return;

	/* Send message
	 * Note: No mutex needed for sending operation, because IO thread is only thread in
	 * TA process, which is sending and receiving -> using socket. */
	send_bytes = com_send_msg(to_fd, msg, msg_len);

	/* Check return values */
	if (send_bytes == COM_RET_IO_ERROR) {
		/* socket is dead or something? Make here function call that figur out
		 * Check errno and make proper task to manager */
	}
}

static void add_msg_done_queue_and_notify(struct ta_task *out_task)
{
	const uint64_t event = 1;

	/* Lock task queue from logic thread */
	if (pthread_mutex_lock(&done_list_mutex)) {
		syslog(LOG_ERR, "add_msg_done_queue: Failed to lock the mutex\n");
		return;
	}

	/* enqueue the task manager queue */
	list_add_before(&out_task->list, &tasks_done.list);

	if (pthread_mutex_unlock(&done_list_mutex)) {
		/* For now, just log error */
		syslog(LOG_ERR, "add_msg_done_queue: Failed to lock the mutex\n");
		return;
	}

	/* notify the I/O thread that there is something at output queue */
	if (write(event_fd, &event, sizeof(uint64_t)) == -1) {
		syslog(LOG_ERR, "add_msg_done_queue: Failed to notify the io thread\n");
		/* TODO: See what is causing it! */
	}
}

static void gen_err_msg(struct ta_task *dst, com_err_t err_origin,
			com_err_t err_name, uint64_t ses_id)
{
	dst->msg_len = sizeof(struct com_msg_error_from_ta);
	dst->msg = calloc(1, dst->msg_len);
	if (!dst->msg) {
		syslog(LOG_ERR, "gen_err_msg: Out of memory\n");
		exit(EXIT_OUT_OF_MEMORY);
	}

	/* Fill error message */
	((struct com_msg_error_from_ta *) dst->msg)->msg_hdr.msg_name = COM_MSG_NAME_ERROR_FROM_TA;
	((struct com_msg_error_from_ta *) dst->msg)->msg_hdr.msg_type = 0; /* ignored */
	((struct com_msg_error_from_ta *) dst->msg)->err_origin = err_origin;
	((struct com_msg_error_from_ta *) dst->msg)->err_name = err_name;
	((struct com_msg_error_from_ta *) dst->msg)->session_id = ses_id;
}


static void gen_err_msg_and_add_to_done(struct ta_task *dst, com_err_t err_origin,
					com_err_t err_name, uint64_t ses_id)
{
	free(dst->msg);
	gen_err_msg(dst, err_origin, err_name, ses_id);
	add_msg_done_queue_and_notify(dst);
}

static void notify_failure_exit(int sockfd)
{
	/* TODO write to the manager and tell them of the failure to setup the TA process
	 * correctly
	 */
	exit(1);
}

static int add_task_todo_queue_and_notify(struct ta_task *task)
{
	if (pthread_mutex_lock(&todo_list_mutex)) {
		syslog(LOG_ERR, "add_task_todo_queue_and_notify: Failed to lock the mutex\n");
		return 1;
	}

	// enqueue the task in our todo list
	list_add_before(&task->list, &tasks_todo.list);

	if (pthread_mutex_unlock(&todo_list_mutex)) {
		syslog(LOG_ERR, "add_task_todo_queue_and_notify: Failed to unlock the mutex\n");
		list_unlink(&task->list);
		return 1;
	}

	// Inform the TA thread that we have a task to be completed
	if (pthread_cond_signal(&condition)) {
		syslog(LOG_ERR, "add_task_todo_queue_and_notify: Failed signal \n");
		list_unlink(&task->list);
		return 1;
	}

	return 0;
}

void handle_sig() {
	/* empty test */
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
	struct ta_task *new_ta_task = NULL;
	int recv_bytes;
	int got_interrupted = 0;
	int ret = -1;
	int msg_len;

	new_ta_task = calloc(1, sizeof(struct ta_task));
	if (!new_ta_task) {
		syslog(LOG_ERR, "receive_from_manager: Out of memory\n");
		exit(1);
	}

	ret = com_recv_msg(man_sockfd, &new_ta_task->msg, &new_ta_task->msg_len, &handle_sig);

	/* If clause is for debug message printing */
	if (ret != 0)
		return;

	add_task_todo_queue_and_notify(new_ta_task);
}

/*!
 * \brief reply_to_manager
 * Notify the manager that we have completed an action
 * \param man_sockfd The socket connection to the manager
 */
static void reply_to_manager(int man_sockfd)
{
	struct ta_task *out_task = NULL;
	uint64_t event;
	int proc_will_be_killed = 0;

	/* Reduce eventfd by one */
	if (read(event_fd, &event, sizeof(uint64_t)) == -1) {
		syslog(LOG_ERR, "reply_to_manager: Failed to reset eventfd\n");
		/* TODO: See what is causing it! */
		return;
	}

	/* Lock from logic thread */
	if (pthread_mutex_lock(&done_list_mutex)) {
		syslog(LOG_ERR, "reply_to_manager: Failed to lock the mutex\n");
		/* Lets hope that errot clear it shelf.. */
		return;
	}

	/* Queue is FIFO and therefore get just fist message */
	out_task = LIST_ENTRY(tasks_done.list.next, struct ta_task, list);
	list_unlink(&out_task->list);

	if (pthread_mutex_unlock(&done_list_mutex)) {
		syslog(LOG_ERR, "reply_to_manager: Failed to unlock the mutex\n");
		return 0;
	}

	send_msg(man_sockfd, out_task->msg, out_task->msg_len);

	free_task(out_task);
}

static void ca_open_session(struct ta_task *in_task)
{
	struct com_msg_open_session *open_msg = in_task->msg;
	TEE_Param params[4]; /* TEMP!! */

	/* Do the task */
	open_msg->return_code_open_session = interface->open_session(0, params, NULL);
}

static void ta_open_session(struct ta_task *in_task)
{
	/* TODO: Handle timout parameter */

	struct com_msg_open_session *open_msg = in_task->msg;
	TEE_Param params[4]; /* TEMP!! */

	/* Do the task */
	open_msg->return_code_open_session = interface->open_session(0, params, NULL);
}

static void open_session(struct ta_task *in_task)
{
	struct com_msg_open_session *open_msg = in_task->msg;

	if (open_msg->msg_hdr.msg_name != COM_MSG_NAME_OPEN_SESSION ||
	    open_msg->msg_hdr.msg_type != COM_TYPE_QUERY) {
		syslog(LOG_ERR, "open_session: Invalid message, ignore\n");
		free_task(in_task);
		return;
	}

	open_msg->return_code_create_entry = TEE_SUCCESS;

	if (open_msg->msg_hdr.sender_type == CA) {
		ca_open_session(in_task);

	} else if (open_msg->msg_hdr.sender_type == TA) {
		ta_open_session(in_task);

	} else {
		syslog(LOG_ERR, "open_session: Invalid sender, ignore\n");
		free_task(in_task);
		return;
	}

	open_msg->return_origin = TEE_ORIGIN_TRUSTED_APP;
	open_msg->msg_hdr.msg_type = COM_TYPE_RESPONSE;
	open_msg->msg_hdr.sender_type = TA;

	add_msg_done_queue_and_notify(in_task);
}

static void ca_invoke_cmd(struct ta_task *in_task)
{
	struct com_msg_invoke_cmd *invoke_msg = in_task->msg;
	TEE_Param params[4]; /* TEMP!! */

	/* Do the task */
	invoke_msg->return_code = interface->invoke_cmd(NULL, invoke_msg->cmd_id, 0, params);
}

static void ta_invoke_cmd(struct ta_task *in_task)
{
	/* TODO: Handle timout parameter */

	struct com_msg_invoke_cmd *invoke_msg = in_task->msg;
	TEE_Param params[4]; /* TEMP!! */

	/* Do the task */
	invoke_msg->return_code = interface->invoke_cmd(NULL, invoke_msg->cmd_id, 0, params);
}

static void invoke_cmd(struct ta_task *in_task)
{
	struct com_msg_invoke_cmd *invoke_msg = in_task->msg;

	if (invoke_msg->msg_hdr.msg_name != COM_MSG_NAME_INVOKE_CMD ||
	    invoke_msg->msg_hdr.msg_type != COM_TYPE_QUERY) {
		syslog(LOG_ERR, "invoke_cmd: Invalid message, ignore\n");
		free_task(in_task);
		return;
	}

	if (invoke_msg->msg_hdr.sender_type == CA) {
		ca_invoke_cmd(in_task);

	} else if (invoke_msg->msg_hdr.sender_type == TA) {
		ta_invoke_cmd(in_task);

	} else {
		syslog(LOG_ERR, "invoke_cmd: Invalid sender, ignore\n");
		free_task(in_task);
		return;
	}

	invoke_msg->return_origin = TEE_ORIGIN_TRUSTED_APP;
	invoke_msg->msg_hdr.msg_type = COM_TYPE_RESPONSE;
	invoke_msg->msg_hdr.sender_type = TA;

	add_msg_done_queue_and_notify(in_task);
}

static int close_session(struct ta_task *in_task)
{
	struct com_msg_close_session *close_msg = in_task->msg;
	uint64_t event = 1;

	if (close_msg->msg_hdr.msg_name != COM_MSG_NAME_CLOSE_SESSION ||
	    close_msg->msg_hdr.msg_type != COM_TYPE_QUERY) {
		syslog(LOG_ERR, "invoke_cmd: Invalid message, ignore\n");
		goto ignore_msg;
	}

	interface->close_session(NULL);

	if (close_msg->should_ta_destroy) {
		interface->destroy();
		free_task(in_task);

		/* notify the I/O thread that it should clean up !*/
		if (write(exit_event_fd, &event, sizeof(uint64_t)) == -1) {
			syslog(LOG_ERR, "close_session: Failed to notify the io thread\n");
			/* TODO: See what is causing it! */
		}

		return 1;
	}

ignore_msg:
	free_task(in_task);
	return 0;
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
	struct ta_task *task;
	com_msg_hdr_t com_msg_name;

	arg = arg;

	for (;;) {
		ret = pthread_mutex_lock(&todo_list_mutex);
		if (ret != 0) {
			strerror_r(errno, errbuf, MAX_ERR_STRING);
			syslog(LOG_ERR, "Failed to lock the mutex : %s\n", errbuf);
			continue;
		}

		// Wait for a task to become available
		while (list_is_empty(&tasks_todo.list)) {
			ret = pthread_cond_wait(&condition, &todo_list_mutex);
			if (ret != 0) {
				strerror_r(errno, errbuf, MAX_ERR_STRING);
				syslog(LOG_ERR, "Failed to wait for condition : %s\n", errbuf);
				continue;
			}
		}

		task = LIST_ENTRY(tasks_todo.list.next, struct ta_task, list);
		list_unlink(&task->list);

		// free the lock so more tasks can be added
		ret = pthread_mutex_unlock(&todo_list_mutex);
		if (ret != 0) {
			strerror_r(errno, errbuf, MAX_ERR_STRING);
			syslog(LOG_ERR, "Failed to unlock the mutex : %s\n", errbuf);
			continue;
		}

		//syslog(LOG_ERR, "ta_internal_api_thread: CMD start: %i\n", com_msg_name);

		/* Exctract messagese part */
		com_msg_name = com_get_msg_name(task->msg);

		switch (com_msg_name) {

		case COM_MSG_NAME_OPEN_SESSION:
			open_session(task);
			break;

		case COM_MSG_NAME_INVOKE_CMD:
			invoke_cmd(task);
			break;

		case COM_MSG_NAME_CLOSE_SESSION:
			if (close_session(task))
				goto cleanup;
			break;

		default:
			/* Just logging an error and message will be ignored */
			syslog(LOG_ERR, "manager_logic_main_thread: Unknow message, ignore\n");
			continue;
		}

		//syslog(LOG_ERR, "ta_internal_api_thread: CMD done : %i\n", com_msg_name);
	}

	/* should never reach here */
	exit(1);
	return NULL;

cleanup:
	/* No cleanup procedures */
	return NULL;
}

static void proc_cleanup(int man_sockfd)
{
	struct list_head *pos;
	struct ta_task *task;

	dlclose(interface->library);
	free(interface);

	/* Return values is discarted! */
	epoll_unreg(man_sockfd);
	epoll_unreg(event_fd);
	epoll_unreg(exit_event_fd);
	close(man_sockfd);
	close(eventfd);
	close(exit_event_fd);

	/* Both mutex *should* be unlocked */
	pthread_mutex_destroy(&done_list_mutex);
	pthread_mutex_destroy(&todo_list_mutex);

	LIST_FOR_EACH(pos, &tasks_done.list) {
		task = LIST_ENTRY(pos, struct ta_task, list);
		free_task(task);
	}

	LIST_FOR_EACH(pos, &tasks_todo.list) {
		task = LIST_ENTRY(pos, struct ta_task, list);
		free_task(task);
	}
}

static void execute_create_entry_point(int man_fd, struct com_msg_open_session *open_msg)
{
	/* Execute command */
	open_msg->return_code_create_entry = interface->create();

	if (open_msg->return_code_create_entry != TEE_SUCCESS) {
		syslog(LOG_ERR, "execute_create_entry_point: Create entry point failed\n");

		/* Update message */
		open_msg->msg_hdr.sender_type = TA;
		open_msg->msg_hdr.msg_type = COM_TYPE_RESPONSE;
		open_msg->return_origin = TEE_ORIGIN_TRUSTED_APP;

		/* Send open message back */
		send_msg(man_fd, open_msg, sizeof(struct com_msg_open_session));

		/* TODO: move own function: Cleanup */
		dlclose(interface->library);
		free(interface);
		pthread_mutex_destroy(&done_list_mutex);
		pthread_mutex_destroy(&todo_list_mutex);
		free(open_msg);
		close(man_fd);
		exit(0);
	}
}

int ta_process_loop(int man_sockfd, sig_status_cb check_signal_status, struct com_msg_open_session *open_msg)
{
	int ret;
	pthread_t ta_thread;
	pthread_attr_t attr;
	char errbuf[MAX_ERR_STRING];
	struct epoll_event cur_events[MAX_CURR_EVENTS];
	int event_count, i;
	struct ta_task *open_ta_task = NULL;

	open_ta_task = calloc(1, sizeof(struct ta_task));
	if (!open_ta_task) {
		syslog(LOG_ERR, "ta_process_loop: Out of memory\n");
		notify_failure_exit(man_sockfd);
	}

	open_ta_task->msg = open_msg;
	open_ta_task->msg_len = sizeof(struct com_msg_open_session);

	/* General data structure initializations */
	INIT_LIST(&tasks_todo.list);
	INIT_LIST(&tasks_done.list);
	interface = NULL;

	ret = load_ta(open_msg->ta_lib_path_witn_name, &interface);
	if (ret != TEE_SUCCESS || interface == NULL) {
		syslog(LOG_ERR, "ta_process_loop: Failed to load the TA");
		notify_failure_exit(man_sockfd);
	}

	execute_create_entry_point(man_sockfd, open_msg);

	/* NOTE: Not yet report to manager about creat entry point function success value.
	 * Lets initialize TA process and report after when TA accepting messages */

	/* create an eventfd, that will allow the writer to increment the count by 1
	 * for each new event, and the reader to decrement by 1 each time, this will allow the
	 * reader to be notified for each new event, as opposed to being notified just once that
	 * there are "event(s)" pending
	 */
	event_fd = eventfd(0, EFD_SEMAPHORE);
	exit_event_fd = eventfd(0, EFD_SEMAPHORE);

	if (init_epoll())
		notify_failure_exit(man_sockfd);

	/* listen to inbound connections from the manager */
	if (epoll_reg_fd(man_sockfd, EPOLLIN))
		notify_failure_exit(man_sockfd);

	/* listen for communications from the TA thread process */
	if (epoll_reg_fd(event_fd, EPOLLIN))
		notify_failure_exit(man_sockfd);

	if (epoll_reg_fd(exit_event_fd, EPOLLIN))
		notify_failure_exit(man_sockfd);

	ret = pthread_attr_init(&attr);
	if (ret) {
		syslog(LOG_ERR, "Failed to create attr for thread %s\n", strerror(errno));
		notify_failure_exit(man_sockfd);
	}

	/* TODO: Should we reserver space for thread stack? */

	ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (ret) {
		syslog(LOG_ERR, "Failed set DETACHED %s\n", strerror(errno));
		notify_failure_exit(man_sockfd);
	}

	ret = pthread_create(&ta_thread, &attr, ta_internal_api_thread, NULL);
	if (ret) {
		syslog(LOG_ERR, "Failed launch thread %s\n", strerror(errno));
		notify_failure_exit(man_sockfd);
	}

	pthread_attr_destroy(&attr);

	if (add_task_todo_queue_and_notify(open_ta_task))
		notify_failure_exit(man_sockfd);

	/* Enter into the main part of this io_thread */
	for (;;) {
		event_count = wrap_epoll_wait(cur_events, MAX_CURR_EVENTS);
		if (event_count == -1) {
			if (errno != EINTR) {
				strerror_r(errno, errbuf, MAX_ERR_STRING);
				syslog(LOG_ERR, "Failed return from epoll_wait : %s\n", errbuf);
				check_signal_status();

				continue;
			}

			check_signal_status();
			/* In both cases continue, and hope the error clears itself */
			continue;
		}

		for (i = 0; i < event_count; i++) {

			if (cur_events[i].data.fd == exit_event_fd) {
				proc_cleanup(man_sockfd);
				exit(1);

			} else if (cur_events[i].data.fd == man_sockfd) {
				receive_from_manager(man_sockfd);

			} else if (cur_events[i].data.fd == event_fd) {
				reply_to_manager(man_sockfd);

			} else {
				syslog(LOG_ERR, "unknown event source:%d\n", cur_events[i].data.fd);
			}
		}
	}

	/* Should never reach here */
	exit(1);
}
