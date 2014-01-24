/****************************************************************************
** Copyright (C) 2014 Brian McGillion.					   **
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

#ifndef __UTILS_API_H__
#define __UTILS_API_H__

#include <stdint.h>
#include "intermediate_data_types.h"
#include "data_types.h"

#define MAX_ERR_STRING 255

/*!
 * \brief intermediate_to_internal_params
 * Create a TEE_Param array from the intermediate format.  This essentially means that we are
 * converting the path name of a shared memory region into a void pointer to the memory region
 * \param i_op The intermediate operation that contains all the data for the command
 * \param params The params array that is to be populated with data
 * \return 0 on success
 */
int32_t intermediate_to_internal_params(const struct inter_operation *i_op, TEE_Param params[4]);

/*!
 * \brief free_params
 * Free any shared memory mappings contained within a paramaters struct
 * \param params The paramaters to be freed
 * \param paramTypes The types associated with each param
 */
void free_params(TEE_Param params[4], int paramTypes);

/*!
 * \brief copy_back_internal_params
 * If the caller passes inout paramaters to the TA, these values must be copied back when
 * the TA is responding.  The shared memory is already taken care of through shared mapping
 * so it is already synchronized
 * \param params The params from which to copy back the data
 * \param i_op The intermediate operation that is returned to the caller
 */
void copy_back_internal_params(const TEE_Param params[4], struct inter_operation *i_op);

#endif
