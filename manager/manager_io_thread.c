/*****************************************************************************
** Copyright (C) 2014 Secure Systems Group.                                 **
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

#include <stdlib.h>
#include <syslog.h>
#include <pthread.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>

#include "com_protocol.h"
#include "manager_io_thread.h"
#include "manager_logic_thread.h"
#include "epoll_wrapper.h"
#include "socket_help.h"
#include "manager_shared_variables.h"
#include "tee_list.h"

static const int MAX_ERR_STRING = 100;
static const int CA_SES_APPROX_COUNT = 20;

static void send_msg(proc_t send_to, void *msg, int msg_len)
{
	int send_bytes;

	if (msg_len == 0)
		return;

	/* Send message
	 * Note: No mutex needed for sending operation, because IO thread is only thread in
	 * manager process, which is sending and receiving -> using socket. */
	if (send_to->p_type == sessionLink)
		send_bytes = com_send_msg(send_to->content.sesLink.sockfd, msg, msg_len);
	else
		send_bytes = com_send_msg(send_to->content.process.sockfd, msg, msg_len);

	/* Check return values */
	if (send_bytes == COM_RET_IO_ERROR) {
		/* TODO: socket is dead or something? Make here function call that figur out
		 * Check errno and make proper task to manager */
		return;
	}

	/* Special case: Open session message responses. Those should also send FD
	 * TODO: Move own function */
	if (com_get_msg_name(msg) == COM_MSG_NAME_OPEN_SESSION &&
	    com_get_msg_type(msg) == COM_TYPE_RESPONSE) {

		if (send_fd(send_to->content.process.sockfd, ((struct com_msg_open_session *)msg)->sess_fd_to_caller) == -1) {
			syslog(LOG_ERR, "send_msg: Failed to send FD");
			/* TODO: Check what is causing error */
		}
	}
}

void handle_signal(uint32_t sig_vector)
{
	syslog(LOG_ERR, "handle_signal: HAHAHAHAAAAAA %u\n", sig_vector);
}

void gen_err_msg(struct manager_msg *dst, com_err_t err_origin, com_err_t err_name, int errno_val)
{
	free(dst->msg);

	dst->msg_len = 0;
	dst->msg = calloc(1, sizeof(struct com_msg_error));
	if (!dst->msg) {
		syslog(LOG_ERR, "gen_err_msg: Out of memory\n");
		return;
	}

	dst->msg_len = sizeof(struct com_msg_error);

	/* Fill error message */
	((struct com_msg_error *) dst->msg)->msg_hdr.msg_name = COM_MSG_NAME_ERROR;
	((struct com_msg_error *) dst->msg)->msg_hdr.msg_type = 0; /* ignored */
	((struct com_msg_error *) dst->msg)->err_origin = err_origin;
	((struct com_msg_error *) dst->msg)->err_name = err_name;
	((struct com_msg_error *) dst->msg)->errno_val = errno_val;
}

void free_manager_msg(struct manager_msg *released_msg)
{
	free(released_msg->msg);
	free(released_msg);
}

void handle_done_queue()
{
	struct manager_msg *handled_msg;
	uint64_t event;

	/* Mark event "done" */
	if (read(event_fd, &event, sizeof(uint64_t)) == -1) {
		syslog(LOG_ERR, "handle_done_queue: Failed to reset eventfd\n");
		/* TODO: See what is causing it! */
	}

	/* Lock from logic thread */
	if (pthread_mutex_lock(&done_queue_mutex)) {
		syslog(LOG_ERR, "handle_done_queue: Failed to lock the mutex\n");
		/* Lets hope that errot clear it shelf.. */
		return;
	}

	/* Queue is FIFO and therefore get just fist message */
	handled_msg = LIST_ENTRY(done_queue.list.next, struct manager_msg, list);
	list_unlink(&handled_msg->list);

	if (pthread_mutex_unlock(&done_queue_mutex)) {
		syslog(LOG_ERR, "handle_done_queue: Failed to unlock the mutex\n");
		return;
	}

	send_msg(handled_msg->proc, handled_msg->msg, handled_msg->msg_len);
	free_manager_msg(handled_msg);
}

void handle_sig()
{
	/* empty test */
}

static void add_msg_to_queue(proc_t ptr)
{
	struct manager_msg *new_man_msg = NULL;
	int ret;

	new_man_msg = calloc(1, sizeof(struct manager_msg));
	if (!new_man_msg) {
		syslog(LOG_ERR, "add_msg_to_queue: Out of memory\n");
		return;
	}

	/* Add message "sender" details */
	new_man_msg->proc = ptr;

	  if (ptr->p_type == sessionLink)
		ret = com_recv_msg(ptr->content.sesLink.sockfd, &new_man_msg->msg, &new_man_msg->msg_len, &handle_sig);
	else
		ret = com_recv_msg(ptr->content.process.sockfd, &new_man_msg->msg, &new_man_msg->msg_len, &handle_sig);

	if (ret == -1) {
		free(new_man_msg);
		return; /* TODO: Figur out why -1 */

	} else if (ret > 0) {
		goto err;
	}

	/* Add task to manager message queue */

	/* Lock task queue from logic thread */
	if (pthread_mutex_lock(&todo_queue_mutex)) {
		syslog(LOG_ERR, "add_msg_to_queue: Failed to lock the mutex\n");
		goto err;
	}

	/* enqueue the task manager queue */
	list_add_before(&new_man_msg->list, &todo_queue.list);

	if (pthread_mutex_unlock(&todo_queue_mutex)) {
		/* For now, just log error
		* TODO: Check what it causing */
		syslog(LOG_ERR, "add_msg_to_queue: Failed to lock the mutex\n");
	}

	/* Signal to logic thread */
	if (pthread_cond_signal(&todo_queue_cond)) {
		/* For now, just log error
		* TODO: Check what it causing */
		syslog(LOG_ERR, "add_msg_to_queue: Manager msg queue signal fail\n");
	}

	return; /* Msg recv OK */

err:
	/* We end up here only when we have problem with mutex.
	 * Notice: No need unlink new task from list, because error will occure before linking to
	 * list or after succesfully linking. */
	gen_err_msg(new_man_msg, TEEC_ORIGIN_TEE, TEEC_ERROR_GENERIC, 0);
	send_msg(ptr, new_man_msg->msg, new_man_msg->msg_len);
	free_manager_msg(new_man_msg);
}

static int add_client_to_ca_table(proc_t add_client)
{
	/* TODO: What is to do, if can not unlock mutex? Possible deadlock situation */

	int ret = 0;

	if (pthread_mutex_lock(&CA_table_mutex)) {
		syslog(LOG_ERR, "add_client_to_ca_table: Failed to lock the mutex\n");
		return -1;
	}

	if (h_table_insert(clientApps, (unsigned char *)(&add_client->content.process.sockfd),
			    sizeof(add_client->content.process.sockfd), add_client)) {
		syslog(LOG_ERR, "add_client_to_ca_table: Failed to add client table(out-of-mem)\n");
		return -1;
	}

	if (pthread_mutex_unlock(&CA_table_mutex)) {
		syslog(LOG_ERR, "add_client_to_ca_table: Failed to unlock the mutex\n");
		return -1;
	}

	return ret;
}

static void send_new_conn_err(int fd)
{
	struct com_msg_error err_msg;

	/* Fill error message */
	err_msg.msg_hdr.msg_name = COM_MSG_NAME_ERROR;
	err_msg.msg_hdr.msg_type = 0; /* ignored */
	err_msg.err_origin = TEEC_ORIGIN_TEE;
	err_msg.err_name = TEEC_ERROR_GENERIC;

	/* Manager is not acting if there is an error, because connection is new and therefore
	 * there is nothing to "clean". */
	com_send_msg(fd, &err_msg, sizeof(struct com_msg_error));
}

void handle_public_fd(int pub_fd)
{
	/* TODO: What if client send data newly accepted fd before it has added epoll? It just
	 * notify that there is some data at FD == No special case? */

	int accept_fd;
	proc_t new_client = NULL;

	/* Socket has received a connection attempt */
	accept_fd = accept(pub_fd, NULL, NULL);
	if (accept_fd == -1) {
		syslog(LOG_ERR, "handle_public_fd: Accept error\n");
		/* hope the problem will clear for next connection */
		return;
	}

	/* Make a entry to proc table */
	/* Create a dummy process entry to monitor the new client and
	 * just listen for future communications from this socket
	 * If there is already data on the socket, we will be notified
	 * immediatly once we return to epoll_wait() and we can handle
	 * it correctly
	 */

	if (create_uninitialized_client_proc(&new_client, accept_fd))
		goto err; /* No resources reserved */

	if (add_client_to_ca_table(new_client))
		goto err; /* Free proc */

	if (epoll_reg_data(accept_fd, EPOLLIN, (void *)new_client))
		goto err; /* Free proc and client table */

	return;
err:
	/* Error message possible, because socket connection is opened.
	 * No mutex needed, because this is new connection */
	send_new_conn_err(accept_fd);
	close(accept_fd);
}

int create_uninitialized_client_proc(proc_t *proc, int sockfd)
{
	*proc = calloc(1, sizeof(struct __proc));
	if (!*proc) {
		syslog(LOG_ERR, "create_uninitialized_client_proc: Out of memory");
		return -1;
	}

	h_table_create(&(*proc)->content.process.links, CA_SES_APPROX_COUNT);
	if (!(*proc)->content.process.links) {
		syslog(LOG_ERR, "create_uninitialized_client_proc: Out of memory");
		return -1;
	}

	(*proc)->content.process.status = Uninitialized;
	(*proc)->content.process.sockfd = sockfd;
	(*proc)->p_type = ClientApp;

	return 0;
}

void pm_handle_connection(uint32_t events, void *proc_ptr)
{
	/* proc_t ptr = (proc_t)proc_ptr; */

	if (events & (EPOLLHUP | EPOLLERR)) {
		/* TODO: Re-think. It is not sufficient just unreg and close FD. Release resource */

		/* The remote end has hung up or is in error so remove the socket from the
		 * epoll listener and explicitedly close this end of the socket

		if (ptr->p_type == sessionLink) {
			epoll_unreg(ptr->sesLink.sockfd);
			close(ptr->sesLink.sockfd);
		} else {
			epoll_unreg(ptr->process.sockfd);
			if (close(ptr->process.sockfd))
				syslog(LOG_ERR, "Could not close the socket: %d", errno);
		}
		exit(1); */
	} else if (events & EPOLLIN) {
		/* We have revceived an input event from a client so we must determine
		 * the session context, if one exists, and pass the message to teh other end of that
		 * session
		 */
		add_msg_to_queue(proc_ptr);
	}
}

void handle_launcher_fd(int launch_fd)
{
	launch_fd = launch_fd;
}
