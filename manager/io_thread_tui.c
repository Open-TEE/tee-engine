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
#include "extern_resources.h"
#include "socket_help.h"
#include "tee_list.h"
#include "tee_logging.h"
#include "h_table.h"

static int tui_socket_fd;
static bool is_display_connected = false;

/* Table to hold TUI requests from TAs */
HASHTABLE tui_requests;

bool is_tui_socket_fd(int socketfd)
{
	return is_display_connected && tui_socket_fd == socketfd;
}

void accept_tui_display_fd(struct epoll_event *event)
{
	int accept_fd;

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
	if (is_display_connected) {
		OT_LOG(LOG_ERR, "Trusted UI Display already connected");
		goto err;
	}
	/* TODO: Look out for possibility to open new listen socket
	 *       only after the previous connection has closed */

	/* TODO: Create new uninitialized TUI Display connection */

	/* Register accepted connection into epoll */
	if (epoll_reg_fd(accept_fd, EPOLLIN))
		goto err;

	tui_socket_fd = accept_fd;
	is_display_connected = true;
	h_table_create(&tui_requests, 5);

	return;

err:
	close(accept_fd);
}

void handle_tui_display_data(struct epoll_event *event)
{
	/* TODO: Implement */

	struct manager_msg *msg = NULL;
	int ret;

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

	/* Receive message */
	ret = com_recv_msg(event->data.fd, &msg->msg, &msg->msg_len);
	if (ret != 0) {
		OT_LOG(LOG_ERR, "Error receiving data from TUI Socket");
		goto err;
	}

	OT_LOG(LOG_ERR, "Read %d", msg->msg_len);
	OT_LOG(LOG_ERR, "%s", ((struct com_msg_tui_display_init *) msg->msg)->test);

	if (add_man_msg_todo_queue_and_notify(msg)) {
		OT_LOG(LOG_ERR, "Failed to add to inbound queue")
		goto err;
	}

	return;

err:
	OT_LOG(LOG_ERR, "Error reading TUI socket, closing socket");

	epoll_unreg(event->data.fd);
	close(tui_socket_fd);

	is_display_connected = false;

	h_table_free(tui_requests);

	free_manager_msg(msg);

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
