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

#include "time_data_types.h"


/*!
 * \brief TEE_GetSystemTime
 * TODO: Figure out if GETTIMEOFDAY is TEE or REE? REE?
 *
 */
void TEE_GetSystemTime(TEE_Time *time);


/* 
 * TODO:  
 * TEE_Result TEE_Wait(uint32_t timeout);
 */


/*
 * TODO 
 * TEE_Result TEE_GetTAPersistentTime(TEE_Time *time);
 */


/*
 * TODO
 * TEE_Result TEE_SetTAPersistentTime(TEE_Time *time);
 */


/*!
 * \brief TEE_GetREETime
 *
 *
 */
void TEE_GetREETime(TEE_Time *time);


#endif /* __TIME_API_H__ */
