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
#include <stdbool.h>
#include <string.h>
#include <time.h>

#include "extern_resources.h"
#include "tee_logging.h"
#include "tui_timeout.h"

pthread_cond_t tui_timeout_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t tui_timeout_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t tui_timeout_thread;
bool tui_timeout_running;

/***
 * \brief Thread for Trusted UI Timeout.
 * \param timeout_param Pointer to timeout in milliseconds.
 */
static void *tui_timeout(void *timeout_param)
{
	uint32_t timeout_msec;
	struct timespec timeout;

	/* Lock Trusted UI State mutex, lock must be acquired before calling
	 * pthread_cond_timedwait. */
	if (pthread_mutex_lock(&tui_state_mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock the mutex");
		goto err;
	}

	/* Timeout was described in display initialization message */
	timeout_msec = ((struct com_msg_tui_display_init *)tui_state.screen_info_data)->timeout;

	/* Get current time */
	if (clock_gettime(CLOCK_REALTIME, &timeout) != 0) {
		OT_LOG(LOG_ERR, "Could not get current time");
		goto err;
	}

	/* Increment current time, as pthread_cond_timedwait
	 * wants absolute time for its timeout */
	timeout.tv_sec += timeout_msec / 1000;

	/* Convert remainder of milliseconds to nanoseconds by multiplying with 10^6 */
	timeout.tv_nsec += (timeout_msec % 1000) * 1000000;

	OT_LOG(LOG_ERR, "pthread_cond_timedwait");

	/* pthread_cond_timedwait will unlock the mutex when it starts waiting,
	 * and lock it again when it continues */
	int pthread_ret = pthread_cond_timedwait(&tui_timeout_cond,
						 &tui_state_mutex,
						 &timeout);
	if (pthread_ret == 0) {
		/* Cancelled, do nothing */
		OT_LOG(LOG_ERR, "Timeout cancelled");

	} else if (pthread_ret == ETIMEDOUT) {
		/* Timed out, ending TUI Session */
		if (tui_state.state == TUI_SESSION) {
			/* Unlock TUI from specific TA */
			tui_state.TA_session_lock = NULL;

			/* State change SESSION -> INITIALIZED */
			OT_LOG(LOG_ERR, "SESSION -> INITIALIZED (Timeout)");
			tui_state.state = TUI_INITIALIZED;
		} else {
			OT_LOG(LOG_ERR, "This should not happen");
		}
	} else {
		/* Error */
		OT_LOG(LOG_ERR, "Error in pthread cond timedwait %s", strerror(pthread_ret));
	}

	/* Unlock Trusted UI State mutex */
	if (pthread_mutex_unlock(&tui_state_mutex))
		OT_LOG(LOG_ERR, "Failed to unlock the mutex");

err:
	/* Lock TUI Timeout mutex */
	if (pthread_mutex_lock(&tui_timeout_mutex))
		OT_LOG(LOG_ERR, "Failed to lock the mutex");

	/* Set state: timeout is not currently running */
	tui_timeout_running = false;

	/* Unlock TUI Timeout mutex */
	if (pthread_mutex_unlock(&tui_timeout_mutex))
		OT_LOG(LOG_ERR, "Failed to unlock the mutex");

	return NULL;
}

int tui_timeout_start()
{
	pthread_attr_t attr;

	/* Lock TUI Timeout mutex */
	if (pthread_mutex_lock(&tui_timeout_mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock the mutex");
		return -1;
	}

	/* Initialize attribute */
	if (pthread_attr_init(&attr) != 0) {
		OT_LOG(LOG_ERR, "pthread_attr_init failed");
		return -2;
	}

	/* Set "Joinable" attribute for thread to be created */
	if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE) != 0) {
		OT_LOG(LOG_ERR, "Could not set attributes for pthread");
		return -3;
	}

	/* TODO: Add EAGAIN loop */
	if (pthread_create(&tui_timeout_thread, &attr, tui_timeout, NULL) != 0) {
		OT_LOG(LOG_ERR, "pthread_create failed");
		return -4;
	}

	/* Set state: timeout is currently running */
	tui_timeout_running = true;

	/* Clean up attribute object, not needed after thread has been created */
	if (pthread_attr_destroy(&attr) != 0) {
		OT_LOG(LOG_ERR, "pthread_attr_destroy failed");
		return -5;
	}

	/* Unlock TUI Timeout mutex */
	if (pthread_mutex_unlock(&tui_timeout_mutex)) {
		OT_LOG(LOG_ERR, "Failed to unlock the mutex");
		return -6;
	}

	return 0;
}

int tui_timeout_cancel()
{
	OT_LOG(LOG_ERR, "1");

	/* Lock TUI Timeout mutex */
	if (pthread_mutex_lock(&tui_timeout_mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock the mutex");
		return -1;
	}

	OT_LOG(LOG_ERR, "2");
	/* If there is no timeout running, don't try to cancel it */
	if (!tui_timeout_running) {
		OT_LOG(LOG_ERR, "No timeout running, not canceled");
		goto fin;
	}

	OT_LOG(LOG_ERR, "3");
	/* Signal the thread that it can stop waiting */
	if (pthread_cond_signal(&tui_timeout_cond) != 0) {
		OT_LOG(LOG_ERR, "Error in pthread_cond_signal");
		return -2;
	}

fin:
	OT_LOG(LOG_ERR, "5");
	/* Unlock TUI Timeout mutex */
	if (pthread_mutex_unlock(&tui_timeout_mutex)) {
		OT_LOG(LOG_ERR, "Failed to unlock the mutex");
		return -4;
	}

	OT_LOG(LOG_ERR, "6");

	return 0;
}
