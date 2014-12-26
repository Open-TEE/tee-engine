/*****************************************************************************
** Copyright (C) 2015 Intel Corporation.                                    **
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
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "com_protocol.h"
#include "extern_resources.h"
#include "h_table.h"
#include "io_thread.h"
#include "shm_mem.h"
#include "socket_help.h"
#include "ta_exit_states.h"
#include "ta_dir_watch.h"
#include "tee_list.h"
#include "tee_logging.h"
#include "logic_thread.h"
#include "logic_thread_tui.h"
#include "tui_timeout.h"

void tui_send_error_msg(uint32_t ret, proc_t destination)
{
	/* Allocate memory for manager message wrapper */
	struct manager_msg *new_man_msg = calloc(1, sizeof(struct manager_msg));
	if (new_man_msg == NULL) {
		OT_LOG(LOG_ERR, "Out of memory\n");
		goto err;
	}

	/* Allocate memory for actual message */
	new_man_msg->msg = calloc(1, sizeof(struct com_msg_tui_error));
	if (new_man_msg->msg == NULL) {
		OT_LOG(LOG_ERR, "Out of memory\n");
		goto err;
	}

	/* Set message length */
	new_man_msg->msg_len = sizeof(struct com_msg_tui_error);

	/* Set destination process to what was given as a parameter */
	new_man_msg->proc = destination;

	/* Set the actual return code into the message */
	((struct com_msg_tui_error *)new_man_msg->msg)->ret = ret;

	/* Queue message to be sent */
	add_msg_out_queue_and_notify(new_man_msg);

	return;
err:
	if (new_man_msg != NULL)
		free(new_man_msg->msg);
	free(new_man_msg);
}

/* TODO: Move to some place accessible from TA as well */
static bool tui_validate_display_init_msg(void *msg, size_t msg_len)
{
	struct com_msg_tui_display_init *init_msg = (struct com_msg_tui_display_init *)msg;
	char *msg_strings = (char *)msg;

	uint32_t i;
	uint32_t cum_len = 0;

	/* Check that message size at least size of its header */
	if (msg_len < sizeof(struct com_msg_tui_display_init)) {
		OT_LOG(LOG_ERR, "Initialization message too small");
		return false;
	}

	/* Assume we have proper structure */
	init_msg = (struct com_msg_tui_display_init *)msg;

	/* Check that the 6 string sizes match the message size */
	if (msg_len != sizeof(struct com_msg_tui_display_init) +
		       init_msg->buttonInfo[0].textLength +
		       init_msg->buttonInfo[1].textLength +
		       init_msg->buttonInfo[2].textLength +
		       init_msg->buttonInfo[3].textLength +
		       init_msg->buttonInfo[4].textLength +
		       init_msg->buttonInfo[5].textLength +
		       6 /* NULL-terminating byte for each string */) {
		OT_LOG(LOG_ERR, "Initialization message expected size mismatch");
		return false;
	}

	/* Verify \0 terminations */
	msg_strings = (char *)(msg + sizeof(struct com_msg_tui_display_init));
	for (i = 0; i < 6; ++i) {
		if (msg_strings[cum_len + init_msg->buttonInfo[i].textLength] != '\0') {
			OT_LOG(LOG_ERR, "Initialization message does not have NUL terminations");
			return false;
		}

		/* Increment cumulative length */
		cum_len += init_msg->buttonInfo[i].textLength + 1;
	}

	return true;
}

void tui_display_init(struct manager_msg *man_msg)
{
	struct com_msg_tui_display_init *msg = man_msg->msg;

	/* Lock Trusted UI State mutex */
	if (pthread_mutex_lock(&tui_state_mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock the mutex");
		return;
	}

	/* Verify message is correct. */
	if (msg->msg_hdr.msg_name != COM_MSG_NAME_TUI_DISPLAY_INIT) {
		OT_LOG(LOG_ERR, "Invalid message type for initialization message");
		goto err;
	}

	/* State must be connected. */
	if (tui_state.state != TUI_CONNECTED) {
		OT_LOG(LOG_ERR, "Display initalization message received in incorrect state");
		goto err;
	}

	/* Display has connected to socket but has not yet introduced itself. */
	/* Expecting message describing the display. */
	/* Message should originate from TUI Display */
	if (man_msg->proc->p_type != proc_t_TUI_Display) {
		OT_LOG(LOG_ERR, "Initialization message did not originate from TUI Display");
		goto err;
	}

	/* TODO: Validate init message format */
	if (!tui_validate_display_init_msg(man_msg->msg, man_msg->msg_len)) {
		OT_LOG(LOG_ERR, "Invalid format in TUI Display Init message");
		tui_reset();
		goto err;
	}

	/* Allocate space for init message caching */
	tui_state.screen_info_data = malloc(man_msg->msg_len);
	if (tui_state.screen_info_data == NULL) {
		OT_LOG(LOG_ERR, "Out of memory");
		goto err;
	}

	/* Cache init message to be responded for GetScreenInfoRequests */
	tui_state.screen_info_data_size = man_msg->msg_len;
	memcpy(tui_state.screen_info_data, man_msg->msg, man_msg->msg_len);

	/* State change: CONNECTED -> INITIALIZED */
	OT_LOG(LOG_ERR, "CONNECTED -> INITIALIZED");
	tui_state.state = TUI_INITIALIZED;

err:
	/* Unlock Trusted UI State mutex */
	if (pthread_mutex_unlock(&tui_state_mutex))
		OT_LOG(LOG_ERR, "Failed to unlock the mutex");

	free_manager_msg(man_msg);
}

void tui_check_text_format(struct manager_msg *man_msg)
{
	struct com_msg_tui_ta2display *msg = man_msg->msg;

	/* Lock Trusted UI State mutex */
	if (pthread_mutex_lock(&tui_state_mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock the mutex");
		return;
	}

	/* Verify message is correct. */
	if (msg->msg_hdr.msg_name != COM_MSG_NAME_TUI_CHECK_TEXT_FORMAT) {
		OT_LOG(LOG_ERR, "Invalid message type");
		goto err;
	}

	/* State must be some of the initialized states */
	if (tui_state.state != TUI_INITIALIZED &&
	    tui_state.state != TUI_SESSION &&
	    tui_state.state != TUI_DISPLAY) {
		OT_LOG(LOG_ERR, "TUICheckTextFormat requested in incorrect state");
		/* Send error response */
		/* TODO: Set proper error */
		tui_send_error_msg(0x420, man_msg->proc);
		goto err;
	}

	if (msg->msg_hdr.msg_type == COM_TYPE_QUERY) {
		/* Add to pending requests table */
		h_table_insert(tui_state.requests,
			       (unsigned char *)(&tui_state.request_id_counter),
			       sizeof(tui_state.request_id_counter),
			       man_msg->proc);

		/* Add request id into message session_id field */
		msg->msg_hdr.sess_id = tui_state.request_id_counter;

		/* Increment counter */
		/* TODO: Overflow and possible overlaps */
		++tui_state.request_id_counter;

		/* Pass message to display */
		man_msg->proc = tui_state.proc;
		add_msg_out_queue_and_notify(man_msg);

		OT_LOG(LOG_ERR, "TUICheckTextFormat: TA -> Display");


	} else if (msg->msg_hdr.msg_type == COM_TYPE_RESPONSE) {
		/* Pass message to TA which originally requested */
		man_msg->proc = h_table_get(tui_state.requests,
					    (unsigned char *)(&msg->msg_hdr.sess_id),
					    sizeof(tui_state.request_id_counter));

		if (man_msg->proc == NULL) {
			OT_LOG(LOG_ERR, "Invalid request id in response");
			goto err;
		}

		/* Remove from pending requests table */
		h_table_remove(tui_state.requests,
			       (unsigned char *)(&msg->msg_hdr.sess_id),
			       sizeof(tui_state.request_id_counter));

		add_msg_out_queue_and_notify(man_msg);
		OT_LOG(LOG_ERR, "TUICheckTextFormat: Display -> TA");
	}

	/* Unlock Trusted UI State mutex */
	if (pthread_mutex_unlock(&tui_state_mutex))
		OT_LOG(LOG_ERR, "Failed to unlock the mutex");

	return;
err:
	/* Unlock Trusted UI State mutex */
	if (pthread_mutex_unlock(&tui_state_mutex))
		OT_LOG(LOG_ERR, "Failed to unlock the mutex");

	free_manager_msg(man_msg);
}

void tui_get_screen_info(struct manager_msg *man_msg)
{
	struct com_msg_tui_ta2display *msg = man_msg->msg;
	struct manager_msg *response_man_msg = NULL;
	struct com_msg_tui_display_init *response_msg = NULL;

	/* Lock Trusted UI State mutex */
	if (pthread_mutex_lock(&tui_state_mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock the mutex");
		return;
	}

	/* Verify message is correct. */
	if (msg->msg_hdr.msg_name != COM_MSG_NAME_TUI_GET_SCREEN_INFO ||
	    msg->msg_hdr.msg_type != COM_TYPE_QUERY) {
		OT_LOG(LOG_ERR, "Invalid message name and/or type");
		goto err;
	}

	/* State must be some of the initialized states */
	if (tui_state.state != TUI_INITIALIZED &&
	    tui_state.state != TUI_SESSION &&
	    tui_state.state != TUI_DISPLAY) {
		OT_LOG(LOG_ERR, "TUIGetScreenInfo requested in incorrect state");
		/* Send error response */
		tui_send_error_msg(TEE_ERROR_BAD_STATE, man_msg->proc);
		goto err;
	}

	/* Allocate memory for "manager message" */
	response_man_msg = calloc(1, sizeof(struct manager_msg));
	if (response_man_msg == NULL) {
		OT_LOG(LOG_ERR, "Out of memory");
		goto err;
	}

	/* Allocate memory for response message itself */
	response_man_msg->msg = calloc(1, tui_state.screen_info_data_size);
	if (response_man_msg->msg == NULL) {
		OT_LOG(LOG_ERR, "Out of memory");
		goto err;
	}

	/* Copy cached message into the response buffer */
	memcpy(response_man_msg->msg,
	       tui_state.screen_info_data,
	       tui_state.screen_info_data_size);
	response_man_msg->msg_len = tui_state.screen_info_data_size;

	/* Replace message name and type */
	response_msg = (struct com_msg_tui_display_init *)response_man_msg->msg;
	response_msg->msg_hdr.msg_name = COM_MSG_NAME_TUI_GET_SCREEN_INFO;
	response_msg->msg_hdr.msg_type = COM_TYPE_RESPONSE;

	/* Set target process as TA that send the query */
	response_man_msg->proc = man_msg->proc;

	/* Send the message */
	add_msg_out_queue_and_notify(response_man_msg);

	OT_LOG(LOG_ERR, "TEE_TUIGetScreenInfo: Manager -> TA");

	/* Unlock Trusted UI State mutex */
	if (pthread_mutex_unlock(&tui_state_mutex))
		OT_LOG(LOG_ERR, "Failed to unlock the mutex");

	free_manager_msg(man_msg);

	return;
err:
	/* Unlock Trusted UI State mutex */
	if (pthread_mutex_unlock(&tui_state_mutex))
		OT_LOG(LOG_ERR, "Failed to unlock the mutex");

	free_manager_msg(man_msg);
	free_manager_msg(response_man_msg);
}

void tui_init_session(struct manager_msg *man_msg)
{
	struct com_msg_tui_ta2display *msg = man_msg->msg;

	/* Lock Trusted UI State mutex */
	if (pthread_mutex_lock(&tui_state_mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock the mutex");
		return;
	}

	/* Verify message is correct. */
	if (msg->msg_hdr.msg_name != COM_MSG_NAME_TUI_INIT_SESSION) {
		OT_LOG(LOG_ERR, "Invalid message type");
		goto err;
	}

	/* Check that session is not already locked, */
	if (tui_state.TA_session_lock != NULL) {
		tui_send_error_msg(TEE_ERROR_BUSY, man_msg->proc);
		goto err;
	}

	/* State must be some of the initialized states */
	if (tui_state.state != TUI_INITIALIZED) {
		OT_LOG(LOG_ERR, "TUIInitSession requested in incorrect state");

		/* Send error response */
		tui_send_error_msg(TEE_ERROR_BAD_STATE, man_msg->proc);
		goto err;
	}

	/* Lock TUI to specific TA */
	tui_state.TA_session_lock = man_msg->proc;

	/* State change INITIALIZED -> SESSION */
	OT_LOG(LOG_ERR, "INITIALIZED -> SESSION");
	tui_state.state = TUI_SESSION;

	/* Start timeout timer */
	/* TODO: Get timeout from the settings */
	tui_timeout_start();

	/* Respond with TEE_SUCCESS */
	tui_send_error_msg(TEE_SUCCESS, man_msg->proc);

err:
	/* Unlock Trusted UI State mutex */
	if (pthread_mutex_unlock(&tui_state_mutex))
		OT_LOG(LOG_ERR, "Failed to unlock the mutex");

	free_manager_msg(man_msg);
}

void tui_close_session(struct manager_msg *man_msg)
{
	struct com_msg_tui_ta2display *msg = man_msg->msg;

	/* Lock Trusted UI State mutex */
	if (pthread_mutex_lock(&tui_state_mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock the mutex");
		return;
	}

	/* Verify message is correct. */
	if (msg->msg_hdr.msg_name != COM_MSG_NAME_TUI_CLOSE_SESSION) {
		OT_LOG(LOG_ERR, "Invalid message type");
		goto err;
	}

	/* State must be some of the in-session states */
	if (tui_state.state == TUI_DISPLAY &&
	    tui_state.TA_session_lock == man_msg->proc) {
		OT_LOG(LOG_ERR, "TUICloseSession requested while display is busy");

		/* Send error response */
		tui_send_error_msg(TEE_ERROR_BUSY, man_msg->proc);
		goto err;
	}

	/* Close Session must be requested by same TA that originally initialized it. */
	if (tui_state.state != TUI_SESSION ||
	    tui_state.TA_session_lock != man_msg->proc) {
		OT_LOG(LOG_ERR, "TUICloseSession requested in incorrect state");

		/* Send error response */
		tui_send_error_msg(TEE_ERROR_BAD_STATE, man_msg->proc);
		goto err;
	}

	/* Unlock TUI from specific TA */
	tui_state.TA_session_lock = NULL;

	/* State change SESSION -> INITIALIZED */
	OT_LOG(LOG_ERR, "SESSION -> INITIALIZED");
	tui_state.state = TUI_INITIALIZED;

	/* Stop timeout timer */
	tui_timeout_cancel();

	/* Respond with TEE_SUCCESS */
	tui_send_error_msg(TEE_SUCCESS, man_msg->proc);

err:
	/* Unlock Trusted UI State mutex */
	if (pthread_mutex_unlock(&tui_state_mutex))
		OT_LOG(LOG_ERR, "Failed to unlock the mutex");

	free_manager_msg(man_msg);
}

void tui_display_screen(struct manager_msg *man_msg)
{
	struct com_msg_tui_ta2display *msg = man_msg->msg;

	/* Lock Trusted UI State mutex */
	if (pthread_mutex_lock(&tui_state_mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock the mutex");
		return;
	}

	/* Verify message is correct. */
	if (msg->msg_hdr.msg_name != COM_MSG_NAME_TUI_DISPLAY_SCREEN) {
		OT_LOG(LOG_ERR, "Invalid message type");
		goto err;
	}

	if (msg->msg_hdr.msg_type == COM_TYPE_QUERY) {
		/* Pass query from TA to Display */

		if (tui_state.state == TUI_DISPLAY) {
			/* Send TEE_ERROR_BUSY error response when already displaying stuff */
			tui_send_error_msg(TEE_ERROR_BUSY, man_msg->proc);
			goto err;
		}

		/* State must be in session but not displaying */
		if (tui_state.state != TUI_SESSION ||
		    tui_state.TA_session_lock != man_msg->proc) {
			OT_LOG(LOG_ERR, "TUIDisplayScreen requested in incorrect state");
			/* Send error response */
			tui_send_error_msg(TEE_ERROR_BAD_STATE, man_msg->proc);
			goto err;
		}

		/* TODO: Only allow in state SESSION */
		/* TODO: Check if SESSION has been locked to TA in question */
		/* Pass message to display */
		man_msg->proc = tui_state.proc;
		add_msg_out_queue_and_notify(man_msg);

		/* Stop timeout timer */
		tui_timeout_cancel();

		/* State Change: SESSION -> DISPLAY */
		tui_state.state = TUI_DISPLAY;

	} else if (msg->msg_hdr.msg_type == COM_TYPE_RESPONSE) {
		/* Pass response from Display to TA */

		if (tui_state.state != TUI_DISPLAY) {
			OT_LOG(LOG_ERR, "Display Screen response received in invalid state");
			goto err;
		}

		/* Pass message to TA */
		man_msg->proc = tui_state.TA_session_lock;

		/* State Change: DISPLAY -> SESSION */
		tui_state.state = TUI_SESSION;

		/* Start session timeout counter */
		tui_timeout_start();
	}

err:
	/* Unlock Trusted UI State mutex */
	if (pthread_mutex_unlock(&tui_state_mutex))
		OT_LOG(LOG_ERR, "Failed to unlock the mutex");
}

/* TODO: Remove */
void tui_display_ta_msg(struct manager_msg *man_msg)
{
	OT_LOG(LOG_ERR, "TUI TA MSG");
	uint8_t msg_name;
	uint8_t msg_type;

	if (pthread_mutex_lock(&tui_state_mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock the mutex");
		return;
	}

	/* TODO: Implement manager process TUI logic */
	struct com_msg_tui_ta2display *msg = man_msg->msg;

	com_get_msg_name(msg, &msg_name);
	com_get_msg_type(msg, &msg_type);
	if (msg_type == COM_TYPE_RESPONSE) {
		OT_LOG(LOG_ERR, "Response message, routing to TA");

		man_msg->proc = h_table_get(tui_state.requests, (unsigned char *)"aa", 2);
		h_table_remove(tui_state.requests, (unsigned char *)"aa", 2);
		add_msg_out_queue_and_notify(man_msg);

	} else if (tui_state.state == TUI_CONNECTED) {
		h_table_insert(tui_state.requests, (unsigned char *)"aa", 2, man_msg->proc);
		man_msg->proc = tui_state.proc;

		OT_LOG(LOG_ERR, "Routing message to TUI Display");

		add_msg_out_queue_and_notify(man_msg);
	} else {
		OT_LOG(LOG_ERR, "Trusted UI Display not connected, dropping");
		/* TODO: Implement error reply to TA */

		free_manager_msg(man_msg);
	}

	if (tui_state.state == TUI_DISCONNECTED) {
		OT_LOG(LOG_ERR, "Trusted UI Display not connected, dropping");
		free_manager_msg(man_msg);
		goto err;
	}

	if (pthread_mutex_unlock(&tui_state_mutex))
		OT_LOG(LOG_ERR, "Failed to unlock the mutex");

	return;

err:
	if (pthread_mutex_unlock(&tui_state_mutex))
		OT_LOG(LOG_ERR, "Failed to unlock the mutex");

	free_manager_msg(man_msg);
}
