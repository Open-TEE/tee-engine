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

#ifndef __INTERMEDIATE_DATA_TYPES_H__
#define __INTERMEDIATE_DATA_TYPES_H__

#include <stdint.h>

#define MAX_SHARED_MEM_PATH 255

/*!
 * \brief The inter_memref struct
 * A structure that can be used to define an intermediate stage between a client API memref
 * and an internal API memref
 */
struct inter_memref {
	char path[MAX_SHARED_MEM_PATH];     /*!< The Path of a created POSIX shared mem region */
	uint64_t size;                      /*!< The size of the shared area */
	uint64_t offset;		    /*!< The offset into the shared memory area */
	uint32_t flags;                     /*!< defines the operating paramaters of the region */
};

/*!
 * \brief The inter_value struct
 * A value structure that replicates the TEEC_Value
 */
struct inter_value {
	uint32_t a;
	uint32_t b;
};

union inter_param{
	struct inter_memref memref;
	struct inter_value value;
};

/*!
 * \brief The inter_operation struct
 * defines a struct that constitutes one whole operation
 */
struct inter_operation {
	uint64_t op_id;              /*!< define a unique id to track the operation */
	uint32_t paramTypes;         /*!< The types of the params that are passed */
	union inter_param params[4]; /*!< The paramaters that are being passed */
	void *session_ctx;           /*!< A session context to keep track of the operation */
};

#endif
