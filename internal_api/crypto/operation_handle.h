/*****************************************************************************
** Copyright (C) 2015 Open-TEE project.	                                    **
** Copyright (C) 2015-2021 Tanel Dettenborn                                 **
** Copyright (C) 2015-2021 Brian McGillion                                  **
** Copyright (C) 2022 Technology Innovation Institute (TII)                 **
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
#include <mbedtls/ecp.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>

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
};

struct __TEE_OperationHandle {
	TEE_OperationInfoMultiple operation_info;
	struct gp_key *key_data;

	/* Using union is not most memory efficient. We could save up to four
	 * pointer, if we would use malloc for structs */
	union {
		struct {
			mbedtls_ecdsa_context *ctx;
			mbedtls_ecp_keypair *ec;
			mbedtls_ecp_group *grp;
		} ecc;
		
		struct {
			mbedtls_rsa_context *ctx;
		} rsa;

		struct {
			uint8_t *key;
			mbedtls_gcm_context *ctx;
		} gcm;

		struct {
			uint8_t *key;
			mbedtls_md_context_t *ctx;
		} md;

		struct {
			uint8_t *key;
			mbedtls_cipher_context_t *ctx;
		} cipher;
	} ctx;
};

#endif /* __OPERATION_HANDLE_H__ */
