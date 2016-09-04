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

#include "../tee_crypto_api.h"
#include "../tee_panic.h"
#include "crypto_digest.h"
#include "crypto_utils.h"
#include "operation_handle.h"



static void do_digest_resume(TEE_OperationHandle operation,
			     HASH_BLOCK_TYPE hash_block_type,
			     uint8_t *chunk,
			     uint32_t chunkSize)
{
	int ret;

	switch (operation->operation_info.algorithm) {
	case TEE_ALG_MD5:
		ret = crypto_hash_resume(HASH_ALG_TYPE_MD5_USE_FW, hash_block_type, chunkSize, chunk, (HASH_CONTEXT *)operation->ctx);
		break;

	case TEE_ALG_SHA1:
		ret = crypto_hash_resume(HASH_ALG_TYPE_SHA1_USE_FW, hash_block_type, chunkSize, chunk, (HASH_CONTEXT *)operation->ctx);
		break;

	case TEE_ALG_SHA256:
		ret = crypto_hash_resume(HASH_ALG_TYPE_SHA256_USE_FW, hash_block_type, chunkSize, chunk, (HASH_CONTEXT *)operation->ctx);
		break;

	case TEE_ALG_SHA224:
		ret = crypto_hash_resume_sha224(hash_block_type, chunkSize, chunk, (UINT8 *)operation->ctx);
		break;

	case TEE_ALG_SHA384:
		ret = crypto_hash_resume_sha384(hash_block_type, chunkSize, chunk, (UINT8 *)operation->ctx);
		break;

	case TEE_ALG_SHA512:
		ret = crypto_hash_resume_sha512(hash_block_type, chunkSize, chunk, (UINT8 *)operation->ctx);
		break;

	default:
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	if (ret != OK)
		TEE_Panic(TEE_ERROR_GENERIC);
}

static void get_hash(TEE_OperationHandle operation,
		     uint8_t *result)
{
	switch (operation->operation_info.algorithm) {
	case TEE_ALG_MD5:
	case TEE_ALG_SHA1:
	case TEE_ALG_SHA256:
		crypto_get_hash((HASH_CONTEXT *)operation->ctx, result);
		break;

	case TEE_ALG_SHA224:
		crypto_get_hash_sha224((UINT8 *)operation->ctx, result);
		break;

	case TEE_ALG_SHA384:
		crypto_get_hash_sha384((UINT8 *)operation->ctx, result);
		break;

	case TEE_ALG_SHA512:
		crypto_get_hash_sha512((UINT8 *)operation->ctx, result);
		break;

	default:
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}
}




/*
 * Crypto digest header functions
 */

TEE_Result init_gp_digest(TEE_OperationHandle operation,
			  uint32_t algorithm)
{
	switch (algorithm) {
	case TEE_ALG_MD5:
	case TEE_ALG_SHA1:
	case TEE_ALG_SHA256:
		operation->ctx = (HASH_CONTEXT *)calloc(1, sizeof(HASH_CONTEXT));
		break;

	case TEE_ALG_SHA224:
		operation->ctx = calloc(1, SHA224_CONTEXT_SIZE);
		break;

	case TEE_ALG_SHA384:
		operation->ctx = calloc(1, SHA384_CONTEXT_SIZE);
		break;

	case TEE_ALG_SHA512:
		operation->ctx = calloc(1, SHA512_CONTEXT_SIZE);
		break;

	default:
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	if (operation->ctx == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	/* Digest has not init function */
	operation->operation_info.digestLength = get_alg_hash_lenght(algorithm);
	operation->operation_info.handleState |= TEE_HANDLE_FLAG_INITIALIZED;
	operation->operation_info.handleState |= TEE_HANDLE_FLAG_KEY_SET;
	operation->operation_info.maxKeySize = 0; /* no key */

	return TEE_SUCCESS;
}

void free_gp_digest(TEE_OperationHandle operation)
{
	free(operation->ctx);
}



/*
 * GP TEE Core API functions
 */

void TEE_DigestUpdate(TEE_OperationHandle operation,
		      void *chunk,
		      uint32_t chunkSize)
{
	HASH_BLOCK_TYPE hash_block_type;

	if (operation == NULL || (chunkSize > 0 && chunk == NULL))
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (operation->operation_info.operationClass != TEE_OPERATION_DIGEST ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED))
		TEE_Panic(TEE_ERROR_BAD_STATE);

	/* First or middle block can't be zero size */
	if (chunkSize == 0)
		TEE_Panic(TEE_ERROR_GENERIC); /* Function is void type */

	if (operation->first_block == true)
		hash_block_type = HASH_FIRST_BLOCK;
	else
		hash_block_type = HASH_MIDDLE_BLOCK;

	do_digest_resume(operation, hash_block_type, (uint8_t *)chunk, chunkSize);

	operation->operation_info.operationState = TEE_OPERATION_STATE_ACTIVE;
	operation->first_block = false;
}

TEE_Result TEE_DigestDoFinal(TEE_OperationHandle operation,
			     void *chunk,
			     uint32_t chunkLen,
			     void *hash,
			     uint32_t *hashLen)
{
	if (operation == NULL || hash == NULL || hashLen == NULL || (chunkLen > 0 && chunk == NULL))
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (operation->operation_info.operationClass != TEE_OPERATION_DIGEST ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED))
		TEE_Panic(TEE_ERROR_BAD_STATE);

	if (operation->operation_info.digestLength > *hashLen)
		return TEE_ERROR_SHORT_BUFFER;

	if (operation->first_block == false) {
		do_digest_resume(operation, HASH_LAST_BLOCK, (uint8_t *)chunk, chunkLen);
		get_hash(operation, (uint8_t *)hash);
	} else {
		do_digest_simple(operation, (uint8_t *)chunk, chunkLen, (uint8_t *)hash);
	}

	*hashLen = operation->operation_info.digestLength;
	TEE_ResetOperation(operation);

	return TEE_SUCCESS;
}
