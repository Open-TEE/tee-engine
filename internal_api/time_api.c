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

#include "time_api.h"

static TEE_Time persistent_time;
static TEE_Time persistent_time_mark;
static int TIME_HAS_SET;


void TEE_GetSystemTime(TEE_Time *time) 
{
	struct timeval tv;

	if(gettimeofday(&tv, 0) == -1)
		return;

	if (UINT32_MAX >= tv.tv_sec && UINT32_MAX >= tv.tv_usec) {
		time->seconds = tv.tv_sec;
		time->millis = (tv.tv_usec + 500) / 1000;
	}
}


TEE_Result TEE_Wait(uint32_t timeout)
{
	/*
	 * TODO: Add cancelabe
	 */

	struct timeval tv;

	if (timeout == TEE_TIMEOUT_INFINITE) {
		while(1) {
			tv.tv_sec = 1;
			tv.tv_usec = 0;
			select(0, NULL, NULL, NULL, &tv);
			/* check cancel flag ? */
		}
	}
	else {
		tv.tv_sec = timeout / 1000;
		tv.tv_usec = (timeout % 1000) * 1000;
		select(0, NULL, NULL, NULL, &tv);
	}
	return TEE_SUCCESS;
}


TEE_Result TEE_GetTAPersistentTime(TEE_Time *time)
{
	if (TIME_HAS_SET == 0)
		return TEE_ERROR_TIME_NOT_SET;

	TEE_Time delta;
	delta_cur_and_mark_time(&delta);

	uint32_t sum = 0;
	if (add_with_overflow_detect(persistent_time.seconds,
				     delta.seconds, &sum) == -1) {
		time->seconds = 0;
		return TEE_ERROR_OVERFLOW;
	}
	time->seconds = sum;

	if (add_with_overflow_detect(persistent_time.millis,
				     delta.millis, &sum) == -1) {
		time->seconds = 0;
		return TEE_ERROR_OVERFLOW;
	}
	time->millis = sum;

	return TEE_SUCCESS;
}


TEE_Result TEE_SetTAPersistentTime(TEE_Time *time)
{
	/*
	 * TODO: Survive reboot
	 */

	TEE_Time time_mark;
	TEE_GetSystemTime(&time_mark);

	if (time == NULL)
		return TEE_ERROR_TIME_NOT_SET; /* this is not correct ret. code */

	memcpy(&persistent_time_mark, &time_mark, sizeof(TEE_Time));
	memcpy(&persistent_time, time, sizeof(TEE_Time));
	TIME_HAS_SET = 1;

	return TEE_SUCCESS;
}


void TEE_GetREETime(TEE_Time *time) 
{
	TEE_GetSystemTime(time);
}

/*
 * Non internal api functions
 */

static void delta_cur_and_mark_time(TEE_Time *delta)
{
	TEE_Time cur;
	TEE_GetSystemTime(&cur);

	if (cur.millis < persistent_time_mark.millis) {
		cur.seconds = cur.seconds - 1;
		cur.millis = cur.millis + 1000;
	}

	delta->seconds = cur.seconds - persistent_time_mark.seconds;
	delta->millis = cur.millis - persistent_time_mark.millis;
}

static int add_with_overflow_detect(const uint32_t a, const uint32_t b, uint32_t *result)
{
	if ( a > 0 && b > 0 &&
	     a > UINT32_MAX - b ) {
		return -1; /* Overflow */
	}

	*result = a + b;
	return 0;
}
