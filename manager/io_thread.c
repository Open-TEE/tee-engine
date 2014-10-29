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

	err_nro = err_nro;
	proc = proc;
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

	err_nro = err_nro;
	fd = fd;
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
	int send_bytes;
	uint8_t msg_name, msg_type;

	if (msg_len == 0)
		return; /* Not an error */

	if (!msg || !send_to) {
		OT_LOG(LOG_ERR, "Sender proc or msg NULL")
		return;
	}

	send_bytes = com_send_msg(send_to->sockfd, msg, msg_len);
	if (send_bytes != msg_len) {
		proc_fd_err(errno, send_to);
		return;
	}

	/* Special case: Open session message responses. Those should also send FD
	 * Question: Hide this dirty code from here to com_protocol? */
	if (com_get_msg_name(msg, &msg_name) || com_get_msg_type(msg, &msg_type))
		return; /* Err msg logged */

	if (msg_name == COM_MSG_NAME_OPEN_SESSION && msg_type == COM_TYPE_RESPONSE) {
		if (send_fd(send_to->sockfd, ((struct com_msg_open_session *)msg)->sess_fd_to_caller) == -1) {
			OT_LOG(LOG_ERR, "Failed to send FD");
			proc_fd_err(errno, send_to);
		}
	}
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

	h_table_remove(clientApps, (unsigned char *)(&rm_client->sockfd), sizeof(rm_client->sockfd));

	if (pthread_mutex_unlock(&CA_table_mutex))
		OT_LOG(LOG_ERR, "Failed to unlock the mutex");
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
