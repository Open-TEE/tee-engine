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
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "com_protocol.h"
#include "core_control_resources.h"
#include "io_thread.h"
#include "io_thread_tui.h"
#include "trusted_ui_state.h"
#include "extern_resources.h"
#include "socket_help.h"
#include "tee_list.h"
#include "tee_logging.h"
#include "h_table.h"

/* Struct for TUI process */
struct __proc tui_proc;

/* Struct to hold Trusted UI state */
struct trusted_ui_state tui_state = {&tui_proc,
				     TUI_DISCONNECTED,
				     NULL};

pthread_mutex_t tui_state_mutex = PTHREAD_MUTEX_INITIALIZER;

bool is_tui_socket_fd(int socketfd)
{
	return tui_state.state == TUI_CONNECTED &&
	       tui_state.proc->sockfd == socketfd;
}

void accept_tui_display_fd(struct epoll_event *event)
{
	int accept_fd;

	if (pthread_mutex_lock(&tui_state_mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock the mutex");
		return;
	}

	OT_LOG(LOG_ERR, "Accepting new Trusted UI Display Connection\n");

	/* TODO: Might not be needed? Function does not do anything */
	/*
	if (check_event_fd_epoll_status(event))
		return; *//* err msg logged */

	/* Socket has received a connection attempt */
	accept_fd = accept(event->data.fd, NULL, NULL);
	if (accept_fd == -1) {
		OT_LOG(LOG_ERR, "Accept error\n");
		/* hope the problem will clear for next connection */
		return;
	}

	/* Check if Display is already connected.
	 * Reject by closing connection immediately after
	 * accepting connection. */
	if (tui_state.state == TUI_CONNECTED) {
		OT_LOG(LOG_ERR, "Trusted UI Display already connected");
		goto err;
	}

	/* TODO: Look out for possibility to open new listen socket
	 *       only after the previous connection has closed */

	/* TODO: Create new uninitialized TUI Display connection */

	/* Register accepted connection into epoll */
	if (epoll_reg_fd(accept_fd, EPOLLIN))
		goto err;

	memset(&tui_proc, 0, sizeof(tui_proc));

	/* Initialize proc_t struct */
	tui_state.proc->sockfd = accept_fd;
	tui_state.proc->p_type = proc_t_TUI_Display;

	/* Set state to connected */
	tui_state.state = TUI_CONNECTED;

	/* Initialize hash table for requests */
	h_table_create(&(tui_state.requests), 5);

	if (pthread_mutex_unlock(&tui_state_mutex))
		OT_LOG(LOG_ERR, "Failed to unlock the mutex");

	return;

err:
	close(accept_fd);

	if (pthread_mutex_unlock(&tui_state_mutex)) {
		OT_LOG(LOG_ERR, "Failed to unlock the mutex");
		return;
	}
}

void handle_tui_display_data(struct epoll_event *event)
{
	/* TODO: Implement */

	struct manager_msg *msg = NULL;
	int ret;

	if (pthread_mutex_lock(&tui_state_mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock the mutex");
		return;
	}

	if (event == NULL)
		return;

	if (!is_tui_socket_fd(event->data.fd))
		return;

	/* TODO: Might not be needed? Function does not do anything */
	/*
	if (check_event_fd_epoll_status(event))
		return; *//* err msg logged */

	msg = calloc(1, sizeof(struct manager_msg));
	if (msg == NULL) {
		OT_LOG(LOG_ERR, "Out of memory\n");
		goto err;
	}

	msg->proc = tui_state.proc;

	/* Receive message */
	ret = com_recv_msg(event->data.fd, &msg->msg, &msg->msg_len);
	if (ret != 0) {
		OT_LOG(LOG_ERR, "Error receiving data from TUI Socket");
		goto err;
	}

	OT_LOG(LOG_ERR, "Read %d", msg->msg_len);

	/* TODO: Route response to correct */

	if (add_man_msg_todo_queue_and_notify(msg)) {
		OT_LOG(LOG_ERR, "Failed to add to inbound queue")
		goto err;
	}

	if (pthread_mutex_unlock(&tui_state_mutex))
		OT_LOG(LOG_ERR, "Failed to unlock the mutex");

	return;
err:
	OT_LOG(LOG_ERR, "Error reading TUI socket, closing socket");

	/* Clean up TUI state */
	epoll_unreg(event->data.fd);
	close(tui_state.proc->sockfd);

	memset(tui_state.proc, 0, sizeof(tui_proc));

	tui_state.state = TUI_DISCONNECTED;

	h_table_free(tui_state.requests);
	tui_state.requests = NULL;

	free_manager_msg(msg);

	if (pthread_mutex_unlock(&tui_state_mutex))
		OT_LOG(LOG_ERR, "Failed to unlock the mutex");

/*
	char buffer[8];
	ssize_t ret;

	ret = read(event->data.fd, buffer, sizeof(buffer) - 1);
	if (ret <= 0) {
		*/
		/* Socket has been closed or other error */
		/*

		epoll_unreg(event->data.fd);
		close(event->data.fd);

		OT_LOG(LOG_ERR, "socket closed");
		return;
	}

	buffer[sizeof(buffer)] = 0;

	OT_LOG(LOG_ERR, "data: %s", buffer);
	*/
}
