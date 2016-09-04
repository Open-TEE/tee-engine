/*****************************************************************************
** Copyright (C) 2015 Open-TEE project.	                                    **
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

#ifndef __OPERATION_HANDLE_H__
#define __OPERATION_HANDLE_H__

#include <mbedtls/rsa.h>

#include "../tee_crypto_api.h"

//const uint32_t GENERIC_BUF_LEN = 32;
#define GENERIC_BUF_LEN 32

struct gp_attributes {
	TEE_Attribute *attrs;
	//Do not change type!!
	//Might mess up serilization funcitons
	uint32_t attrs_count;
};

struct gp_key {

	/* Reference count is set zero at TEE_AllocateTransientObject
	 * Count is increaset: TEE_CreatePersistentObject (if object parameter countaint key)
	 *						TEE_PopulateTransientObject
	 *						TEE_CopyObjectAttributes1
	 *						TEE_CopyOperation
	 *						TEE_SetOperationKey
	 *
	 * Count is decreaset: TEE_FreeTransientObject
	 *					   TEE_FreeOpeation
	 *					   TEE_CloseObject
	 *					   TEE_CloseAndDeletePersistentObject
	 *					   TEE_SetOperationKey
	 * After decrement the variable is checked and if it zero, key will be destroyed */
	uint32_t reference_count;

	/* Key is always signed to object or operation and these values could be
	 * queried from object/operation info. These are here for usability sake */
	uint32_t gp_key_type;
	uint32_t key_lenght; /* in bytes */
	uint32_t key_max_length; /* in bytes */

	/* Parameters are assigned to key with TEE_PopulateTransientObject() */
	struct gp_attributes gp_attrs;

	/* Using union is not most memory efficient. We could save up to four
	 * pointer, if we would use malloc for structs */
	union {

		/* For RSA: mbedtls is storing RSA key into context. */
		struct {
			mbedtls_rsa_context ctx;
		} rsa;

		/* For AES, DES and HMAC (at least) */
		struct {
			uint8_t *key;
			
			//TODO (improvement): Reduce memory footprint
			//Generic buffer. Currently used with AES CTR
			uint8_t genericBuf[GENERIC_BUF_LEN];
			uint32_t genericVar;
			
		} secret;

	} key;
};

struct __TEE_OperationHandle {
	TEE_OperationInfoMultiple operation_info;
	void *ctx; /* Operation specific */
	struct gp_key *key_data;
};

#endif /* __OPERATION_HANDLE_H__ */
