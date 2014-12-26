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
#include "logic_thread_tui.h"
#include "trusted_ui_state.h"
#include "extern_resources.h"
#include "socket_help.h"
#include "tee_list.h"
#include "tee_logging.h"
#include "tui_timeout.h"
#include "h_table.h"

/* Struct for TUI process */
struct __proc tui_proc;

/* Struct to hold Trusted UI state */
struct trusted_ui_state tui_state;

pthread_mutex_t tui_state_mutex = PTHREAD_MUTEX_INITIALIZER;

bool is_tui_socket_fd(int socketfd)
{
	return tui_state.state != TUI_DISCONNECTED &&
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

	/* Register accepted connection into epoll */
	if (epoll_reg_fd(accept_fd, EPOLLIN))
		goto err;

	/* Initialize Trusted UI global state */
	memset(&tui_state, 0, sizeof(tui_state));
	tui_state.state = TUI_DISCONNECTED;
	tui_state.proc = &tui_proc;

	memset(&tui_proc, 0, sizeof(tui_proc));

	/* Initialize proc_t struct */
	tui_state.proc->sockfd = accept_fd;
	tui_state.proc->p_type = proc_t_TUI_Display;

	/* Set state to connected */
	OT_LOG(LOG_ERR, "DISCONNECTED -> CONNECTED");
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

void tui_reset()
{
	proc_t ta;

	/* Unregister epoll and close socket */
	epoll_unreg(tui_state.proc->sockfd);
	close(tui_state.proc->sockfd);

	if (tui_state.state == TUI_DISPLAY) {
		/* If currently displaying screen, send error message as reply,
		 * to unblock TA */
		tui_send_error_msg(TEE_ERROR_GENERIC, tui_state.TA_session_lock);
	}

	/* Send error message to all TAs waiting for reply,
	 * so TAs won't get stuck waiting for replies */
	h_table_init_stepper(tui_state.requests);
	for (ta = h_table_step(tui_state.requests);
	     ta != NULL;
	     ta = h_table_step(tui_state.requests)) {
		tui_send_error_msg(TEE_ERROR_GENERIC, ta);
	}

	/* Cancel possible timeout */
	tui_timeout_cancel();

	/* Empty request table */
	h_table_free(tui_state.requests);
	tui_state.requests = NULL;

	/* Free cached screen info */
	free(tui_state.screen_info_data);
	tui_state.screen_info_data = NULL;
	tui_state.screen_info_data_size = 0;

	/* Reset Trusted UI process info */
	memset(tui_state.proc, 0, sizeof(tui_proc));

	/* Reset Trusted UI global state */
	OT_LOG(LOG_ERR, "Reset Trusted UI state");
	memset(&tui_state, 0, sizeof(tui_state));
	tui_state.state = TUI_DISCONNECTED;
	tui_state.proc = &tui_proc;
}

void handle_tui_display_data(struct epoll_event *event)
{
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

	if (add_man_msg_todo_queue_and_notify(msg)) {
		OT_LOG(LOG_ERR, "Failed to add to inbound queue")
		goto err;
	}

	if (pthread_mutex_unlock(&tui_state_mutex))
		OT_LOG(LOG_ERR, "Failed to unlock the mutex");

	return;
err:
	OT_LOG(LOG_ERR, "Error reading TUI socket, closing socket");

	/* On error, reset Trusted UI manager */
	tui_reset();

	free_manager_msg(msg);

	if (pthread_mutex_unlock(&tui_state_mutex))
		OT_LOG(LOG_ERR, "Failed to unlock the mutex");

}
