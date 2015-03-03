/****************************************************************************
** Copyright (C) 2013 ICRI.						   **
**									   **
** Licensed under the Apache License, Version 2.0 (the "License");	   **
** you may not use this file except in compliance with the License.	   **
** You may obtain a copy of the License at				   **
**									   **
** http://www.apache.org/licenses/LICENSE-2.0				   **
**									   **
** Unless required by applicable law or agreed to in writing, software	   **
** distributed under the License is distributed on an "AS IS" BASIS,	   **
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.**
** See the License for the specific language governing permissions and	   **
** limitations under the License.					   **
*****************************************************************************/

#include <sys/time.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/select.h>

#include "tee_time_api.h"

static struct timeval persistent_time;
static struct timeval mark_time;
static bool TIME_IS_SET;

void TEE_GetSystemTime(TEE_Time *time)
{
	struct timeval tv;

	if (gettimeofday(&tv, 0) == -1)
		return;

	time->seconds = tv.tv_sec;
	time->millis = tv.tv_usec / 1000;
}

TEE_Result TEE_Wait(uint32_t timeout)
{
	struct timeval tv;
	struct timeval *tv_ptr = NULL;
	uint32_t ret = TEE_SUCCESS;

	if (timeout != TEE_TIMEOUT_INFINITE) {
		tv.tv_sec = timeout / 1000;
		tv.tv_usec = timeout % 1000;
		tv_ptr = &tv;
	}

	if (select(0, NULL, NULL, NULL, tv_ptr) == -1) {
		if (errno == EINTR)
			ret = TEE_ERROR_CANCEL; /* TODO: use signal interrupts or poll a flag ? */
		else
			ret = TEE_ERROR_GENERIC;
	}

	return ret;
}

TEE_Result TEE_GetTAPersistentTime(TEE_Time *time)
{
	struct timeval tv;
	struct timeval diff_time;

	if (time == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if (TIME_IS_SET == 0)
		return TEE_ERROR_TIME_NOT_SET;

	/* Get the current time */
	gettimeofday(&tv, NULL);

	/* check if the current time is less than the mark time. This would indicate that
	 * the clock has been reset, so we can no longer trust it as a source thus we must request a
	 * reset */
	if (timercmp(&tv, &mark_time, < ))
		return TEE_ERROR_TIME_NEEDS_RESET;

	/* Calculate the delta between now and when the persistent time was set */
	timersub(&tv, &mark_time, &diff_time);

	/* calculate the "current" persistent time */
	timeradd(&persistent_time, &diff_time, &tv);

	time->seconds = tv.tv_sec;
	time->millis = tv.tv_usec * 1000;

	/* TODO store the persistent time and base time into a file and reload them on TA boot */

	return TEE_SUCCESS;
}

TEE_Result TEE_SetTAPersistentTime(TEE_Time *time)
{
	if (time == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	/* mark the current time when this function is called so we can use it to calculate the
	 * amount of time that has past when we call get persistent time */
	gettimeofday(&mark_time, NULL);

	persistent_time.tv_sec = time->seconds;
	persistent_time.tv_usec = time->millis / 1000;

	TIME_IS_SET = true;

	return TEE_SUCCESS;
}

void TEE_GetREETime(TEE_Time *time)
{
	TEE_GetSystemTime(time);
}
