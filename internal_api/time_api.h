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

#ifndef __TIME_API_H__
#define __TIME_API_H__

#include <stdint.h>

#include "data_types.h"

/*
 * Data types
 */

#define TEE_TIMEOUT_INFINITE		0xFFFFFFFF

typedef struct {
	uint32_t seconds;
	uint32_t millis;
} TEE_Time;


/*
 * Internal api functions
 */

/*!
 * \brief TEE_GetSystemTime
 * \param time
 */
void TEE_GetSystemTime(TEE_Time *time);


/*!
 * \brief TEE_Wait
 * TODO: Add cancelable
 * \param timeout
 * \return
 */
TEE_Result TEE_Wait(uint32_t timeout);


/*!
 * \brief TEE_GetTAPersistentTime
 * \param time
 * \return
 */
TEE_Result TEE_GetTAPersistentTime(TEE_Time *time);


/*!
 * \brief TEE_SetTAPersistentTime
 * \param time
 * \return
 */
TEE_Result TEE_SetTAPersistentTime(TEE_Time *time);


/*!
 * \brief TEE_GetREETime
 * Function Calling GetSystemTime -function. \sa GetSystemTime
 * \param time
 */
void TEE_GetREETime(TEE_Time *time);


/*
 * Non internal api functions
 */

/*!
 * \brief add_with_overflow_detect
 * \param a
 * \param b
 * \param result
 * \return If overflow detected, -1 is returned. 0 on success.
 */
static int add_with_overflow_detect(const uint32_t a, const uint32_t b, uint32_t *result);

/*!
 * \brief delta_cur_and_mark_time
 * Calculating delta between current time (using GetSystemTime \sa GetSystemTime)
 * and persistant time mark.
 * \param delta is filled with delta
 */
static void delta_cur_and_mark_time(TEE_Time *delta);

#endif /* __TIME_API_H__ */
