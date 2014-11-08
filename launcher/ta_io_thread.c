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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "com_protocol.h"
#include "epoll_wrapper.h"
#include "ta_exit_states.h"
#include "ta_io_thread.h"
#include "tee_logging.h"

static void terminate_ta_gracefully()
{
	/* Placeholder */

	exit(TA_EXIT_PANICKED);
}

static void fd_error(int fd_errno)
{
	switch (fd_errno) {
	case EINVAL:
	case EPIPE:
	case EBADF:
	case EIO: /* ? */
		terminate_ta_gracefully();
		break;

	case EDQUOT:
	case ENOSPC:
	case EFBIG:
	case EFAULT:
	case EAGAIN: /* EWOULDBLOCK */
	case EINTR:
	case EDESTADDRREQ:
	case EISDIR:
		OT_LOG(LOG_DEBUG, "No action: %s", strerror(fd_errno))
		break;

	default:
		OT_LOG(LOG_DEBUG, "Unknown errno: %s", strerror(fd_errno))
	}
}

static void add_task_todo_queue_and_notify(struct ta_task *task)
{
	if (pthread_mutex_lock(&todo_list_mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock the mutex: %s", strerror(errno));
		free_task(task);
		return;
	}

	/* enqueue the task in our todo list */
	list_add_before(&task->list, &tasks_todo.list);

	if (pthread_mutex_unlock(&todo_list_mutex)) {
		OT_LOG(LOG_ERR, "Failed to unlock the mutex: %s", strerror(errno))
		return;
	}

	/* Inform the TA thread that we have a task to be completed */
	if (pthread_cond_signal(&condition)) {
		OT_LOG(LOG_ERR, "Failed signal: %s", strerror(errno))
	}
}

static void send_msg(int to_fd, void *msg, int msg_len)
{
	if (msg_len == 0)
		return;

	if (com_send_msg(to_fd, msg, msg_len) == -1) {
		OT_LOG(LOG_ERR, "Message sending failed: %s", strerror(errno));
		/* Note: Function may return -1 for out of memory, but fd_error will not
		 * react this error. Lets hope this will clear it self or OOM killer act */
		fd_error(errno);
	}
}

void free_task(struct ta_task *released_task)
{
	free(released_task->msg);
	free(released_task);
}

void receive_from_manager(struct epoll_event *event, int man_sockfd)
{
	struct ta_task *new_ta_task = NULL;
	int ret;

	if (event->events & (EPOLLHUP | EPOLLERR)) {
		OT_LOG(LOG_ERR, "Manger sock problem");
		terminate_ta_gracefully();
	}

	new_ta_task = calloc(1, sizeof(struct ta_task));
	if (!new_ta_task) {
		OT_LOG(LOG_ERR, "Out of memory");
		return;
	}

	ret = com_recv_msg(man_sockfd, &new_ta_task->msg, &new_ta_task->msg_len);
	if (ret != 0) {

		free(new_ta_task);

		if (ret == -1)
			fd_error(errno);
		else if (ret > 0)
			OT_LOG(LOG_ERR, "discarding msg");

		return;
	}

	add_task_todo_queue_and_notify(new_ta_task);
}

void reply_to_manager(struct epoll_event *event, int man_sockfd)
{
	struct ta_task *out_task = NULL;
	uint64_t event_fd_event;

	if (event->events & (EPOLLHUP | EPOLLERR)) {
		OT_LOG(LOG_ERR, "Event fd problem");
		terminate_ta_gracefully();
	}

	/* Reduce eventfd by one */
	if (read(event_fd, &event_fd_event, sizeof(uint64_t)) == -1) {
		OT_LOG(LOG_ERR, "Failed to reset eventfd");
		fd_error(errno);
		return;
	}

	/* Lock from logic thread */
	if (pthread_mutex_lock(&done_list_mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock the mutex: %s", strerror(errno))
		/* Lets hope that errot clear it shelf.. */
		return;
	}

	/* Queue is FIFO and therefore get just fist message */
	out_task = LIST_ENTRY(tasks_done.list.next, struct ta_task, list);
	list_unlink(&out_task->list);

	if (pthread_mutex_unlock(&done_list_mutex)) {
		OT_LOG(LOG_ERR, "Failed to unlock the mutex: %s", strerror(errno))
	}

	send_msg(man_sockfd, out_task->msg, out_task->msg_len);

	free_task(out_task);
}
