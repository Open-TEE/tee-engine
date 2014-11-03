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
#include <string.h>
#include <unistd.h>

#include "com_protocol.h"
#include "io_thread.h"
#include "extern_resources.h"
#include "socket_help.h"
#include "tee_list.h"
#include "tee_logging.h"

/* Used for hashtable init */
#define CA_SES_APPROX_COUNT 20

/*!
 * \brief proc_fd_err
 * Process fd is erring
 * \param err_nro
 * \param fd
 * \param proc
 */
static void proc_fd_err(int err_nro, proc_t proc)
{
	/* Placeholder */

	if (proc)
		epoll_unreg(proc->sockfd);

	err_nro = err_nro;
}

/*!
 * \brief check_proc_fd_epoll_status
 * Checks process fd status and acts according to status. Function checks epoll events (== status)
 * \param event
 * \return
 */
static int check_proc_fd_epoll_status(struct epoll_event *event)
{
	/* Placeholder */

	if (event->events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
		epoll_unreg(((proc_t)event->data.ptr)->sockfd);
		return 1;
	}

	if (event->events & EPOLLIN) {
		return 0;
	}

	OT_LOG(LOG_ERR, "unknown epoll event");
	return 1;
}

/*!
 * \brief io_fd_err
 * One of IO thread event fd is erring
 * \param err_nro
 * \param fd
 */
static void io_fd_err(int err_nro, int fd)
{
	/* Placeholder */

	epoll_unreg(fd);
	err_nro = err_nro;
}

/*!
 * \brief check_event_fd_epoll_status
 * Checks event fd status and acts according to status. For example event_done_queue_fd.
 * \param event
 * \return
 */
static int check_event_fd_epoll_status(struct epoll_event *event)
{
	/* Placeholder */

	event = event;
	return 0;
}

static void send_msg(proc_t send_to, void *msg, int msg_len)
{
	uint8_t msg_name, msg_type;

	if (msg_len == 0)
		return; /* Not an error */

	if (!msg || !send_to) {
		OT_LOG(LOG_ERR, "Sender proc or msg NULL")
		return;
	}

	if (com_send_msg(send_to->sockfd, msg, msg_len) != msg_len) {
		proc_fd_err(errno, send_to);
		return;
	}

	/* Special case: Open session message responses. Those should also send FD
	 * Question: Hide this dirty code from here to com_protocol? */
	if (com_get_msg_name(msg, &msg_name) || com_get_msg_type(msg, &msg_type))
		return; /* Err msg logged */

	if (msg_name == COM_MSG_NAME_OPEN_SESSION && msg_type == COM_TYPE_RESPONSE) {
		if (send_fd(send_to->sockfd,
			    ((struct com_msg_open_session *)msg)->sess_fd_to_caller) == -1) {
			OT_LOG(LOG_ERR, "Failed to send FD");
			proc_fd_err(errno, send_to);
		}
	}
}

static void send_err_msg(proc_t proc, uint32_t err, uint32_t err_origin)
{
	struct com_msg_error err_msg;

	memset(&err_msg, 0, sizeof(struct com_msg_error));
	err_msg.msg_hdr.msg_name = COM_MSG_NAME_ERROR;

	err_msg.ret = err;
	err_msg.ret_origin = err_origin;

	if (com_send_msg(proc->sockfd, &err_msg, sizeof(struct com_msg_error)) !=
	    sizeof(struct com_msg_error))
		proc_fd_err(errno, proc);
}

static void send_new_conn_err(int fd)
{
	struct com_msg_ca_init_tee_conn err_msg;

	err_msg.msg_hdr.msg_name = COM_MSG_NAME_CA_INIT_CONTEXT;
	err_msg.msg_hdr.msg_type = COM_TYPE_RESPONSE;
	err_msg.ret = TEE_ERROR_GENERIC;

	com_send_msg(fd, &err_msg, sizeof(struct com_msg_ca_init_tee_conn));
}

static int create_uninitialized_client_proc(proc_t *proc, int sockfd)
{
	*proc = calloc(1, sizeof(struct __proc));
	if (!*proc) {
		OT_LOG(LOG_ERR, "Out of memory");
		return 1;
	}

	h_table_create(&(*proc)->content.process.links, CA_SES_APPROX_COUNT);
	if (!(*proc)->content.process.links) {
		OT_LOG(LOG_ERR, "Out of memory");
		free(*proc);
		return 1;
	}

	(*proc)->content.process.status = proc_uninitialized;
	(*proc)->sockfd = sockfd;
	(*proc)->p_type = proc_t_CA;

	return 0;
}

static int add_client_to_ca_table(proc_t add_client)
{
	int ret = 0;

	if (pthread_mutex_lock(&CA_table_mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock the mutex");
		return 1;
	}

	if (h_table_insert(clientApps, (unsigned char *)(&add_client->sockfd),
			   sizeof(add_client->sockfd), add_client)) {
		OT_LOG(LOG_ERR, "Failed to add client table(out-of-mem)");
		ret = 1;
	}

	if (pthread_mutex_unlock(&CA_table_mutex))
		OT_LOG(LOG_ERR, "Failed to unlock the mutex");

	return ret;
}

static void remove_client_from_ca_table(proc_t rm_client)
{
	if (pthread_mutex_lock(&CA_table_mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock the mutex");
		return;
	}

	h_table_remove(clientApps, (unsigned char *)(&rm_client->sockfd),
		       sizeof(rm_client->sockfd));

	if (pthread_mutex_unlock(&CA_table_mutex))
		OT_LOG(LOG_ERR, "Failed to unlock the mutex");
}

static int add_man_msg_todo_queue_and_notify(struct manager_msg *msg)
{
	int ret = 0;

	/* Lock task queue from logic thread */
	if (pthread_mutex_lock(&todo_queue_mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock the mutex");
		return 1;
	}

	/* enqueue the task manager queue */
	list_add_before(&msg->list, &todo_queue.list);

	if (pthread_mutex_unlock(&todo_queue_mutex)) {
		OT_LOG(LOG_ERR, "Failed to unlock the mutex");
		ret = 1;
	}

	/* Signal to logic thread */
	if (pthread_cond_signal(&todo_queue_cond)) {
		OT_LOG(LOG_ERR, "Manager msg queue signal fail");
		/* Function only should fail if todo_queue_cond is not initialized
		 * Therefore, this function call *should* not fails */
		ret = 1; /* error return, because no granti if message get handeled! */
	}

	return ret;
}

void free_manager_msg(struct manager_msg *released_msg)
{
	free(released_msg->msg);
	free(released_msg);
}

void handle_done_queue(struct epoll_event *event)
{
	struct manager_msg *handled_msg = NULL;
	uint64_t done_event;

	if (check_event_fd_epoll_status(event))
		return; /* err msg logged */

	/* Reduce eventfd by one */
	if (read(event_done_queue_fd, &done_event, sizeof(uint64_t)) == -1) {
		OT_LOG(LOG_ERR, "Failed to reset eventfd");
		io_fd_err(errno, event_done_queue_fd);
	}

	/* Lock from logic thread */
	if (pthread_mutex_lock(&done_queue_mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock the mutex");
		/* Lets hope that errot clear it shelf.. */
		return;
	}

	if (!list_is_empty(&done_queue.list)) {
		/* Queue is FIFO and therefore get just fist message */
		handled_msg = LIST_ENTRY(done_queue.list.next, struct manager_msg, list);
		list_unlink(&handled_msg->list);
	}

	if (pthread_mutex_unlock(&done_queue_mutex))
		OT_LOG(LOG_ERR, "Failed to unlock the mutex");

	if (!handled_msg)
		return;

	send_msg(handled_msg->proc, handled_msg->msg, handled_msg->msg_len);

	free_manager_msg(handled_msg);
}

void handle_public_fd(struct epoll_event *event)
{
	int accept_fd;
	proc_t new_client = NULL;

	if (check_event_fd_epoll_status(event))
		return; /* err msg logged */

	/* Socket has received a connection attempt */
	accept_fd = accept(event->data.fd, NULL, NULL);
	if (accept_fd == -1) {
		OT_LOG(LOG_ERR, "Accept error\n");
		/* hope the problem will clear for next connection */
		return;
	}

	if (create_uninitialized_client_proc(&new_client, accept_fd))
		goto err_1; /* No resources reserved */

	if (add_client_to_ca_table(new_client))
		goto err_2; /* Free proc */

	if (epoll_reg_data(accept_fd, EPOLLIN, (void *)new_client))
		goto err_3; /* Free proc and client table */

	return;

err_3:
	remove_client_from_ca_table(new_client);
err_2:
	h_table_free(new_client->content.process.links);
	free(new_client);
err_1:
	send_new_conn_err(accept_fd);
	close(accept_fd);
}

void read_fd_and_add_todo_queue(struct epoll_event *event)
{
	struct manager_msg *new_man_msg = NULL;
	int ret;

	/* Process might have cleaned up */
	if (!event || !event->data.ptr)
		return;

	/* Function is only valid for proc FDs */
	if (((proc_t)event->data.ptr)->p_type >= proc_t_last) {
		OT_LOG(LOG_ERR, "Invalid connection type")
		return;
	}

	if (check_proc_fd_epoll_status(event))
		return; /* err msg logged */

	new_man_msg = calloc(1, sizeof(struct manager_msg));
	if (!new_man_msg) {
		OT_LOG(LOG_ERR, "Out of memory\n");
		goto err;
	}

	/* Add message "sender" details */
	new_man_msg->proc = event->data.ptr;

	/* Add message */
	ret = com_recv_msg(new_man_msg->proc->sockfd, &new_man_msg->msg, &new_man_msg->msg_len);
	if (ret == -1) {
		OT_LOG(LOG_ERR, "Socket error");
		proc_fd_err(errno, new_man_msg->proc);
		free(new_man_msg);
		return; /* No error message to CA, because socket status is unknown! */

	} else if (ret > 0) {
		OT_LOG(LOG_ERR, "Received corrupted/partial message, discarding");
		goto err;
	}

	/* Add task to manager message queue */
	if (add_man_msg_todo_queue_and_notify(new_man_msg))
		goto err;

	return; /* Msg recv OK */

err:
	send_err_msg(event->data.ptr, TEE_ERROR_GENERIC, TEE_ORIGIN_TEE);
	free_manager_msg(new_man_msg);
}

void handle_close_sock(struct epoll_event *event)
{
	struct sock_to_close *fd_to_close = NULL;
	struct list_head *pos;
	uint64_t close_event;

	if (check_event_fd_epoll_status(event))
		return; /* err msg logged */

	/* Read all events */
	if (read(event_close_sock, &close_event, sizeof(uint64_t)) == -1) {
		OT_LOG(LOG_ERR, "Failed to reset eventfd");
		io_fd_err(errno, event_close_sock);
	}

	/* Lock task queue from logic thread */
	if (pthread_mutex_lock(&socks_to_close_mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock the mutex");
		return;
	}

	if (!list_is_empty(&socks_to_close.list)) {

		LIST_FOR_EACH(pos, &socks_to_close.list) {
			fd_to_close = LIST_ENTRY(pos, struct sock_to_close, list);
			close(fd_to_close->sockfd);
			free(fd_to_close);
		}
	}
	if (pthread_mutex_unlock(&socks_to_close_mutex))
		OT_LOG(LOG_ERR, "Failed to lock the mutex");
}
