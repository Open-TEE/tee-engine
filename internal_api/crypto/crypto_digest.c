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
#include "../tee_memory.h"
#include "crypto_digest.h"
#include "crypto_utils.h"
#include "operation_handle.h"
#include "tee_logging.h"

#include <mbedtls/md.h>

static mbedtls_md_type_t gp_mac_to_mbedtls(uint32_t mac_type)
{
	switch (mac_type) {
	case TEE_ALG_MD5:
		return MBEDTLS_MD_MD5;
	case TEE_ALG_SHA1:
		return MBEDTLS_MD_SHA1;
	case TEE_ALG_SHA224:
		return MBEDTLS_MD_SHA224;
	case TEE_ALG_SHA256:
		return MBEDTLS_MD_SHA256;
	case TEE_ALG_SHA384:
		return MBEDTLS_MD_SHA384;
	case TEE_ALG_SHA512:
		return MBEDTLS_MD_SHA512;
	default:
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	return MBEDTLS_MD_NONE;
}

static TEE_Result do_md_init(TEE_OperationHandle operation)
{
	const mbedtls_md_info_t *md_info;
	mbedtls_md_context_t *md_ctx = NULL;

	md_info = mbedtls_md_info_from_type(gp_mac_to_mbedtls(operation->operation_info.algorithm));

	md_ctx = (mbedtls_md_context_t *)TEE_Malloc(sizeof(mbedtls_md_context_t), 1);
	if (md_ctx == NULL) {
		OT_LOG(LOG_ERR, "No memory for context");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	mbedtls_md_init(md_ctx);

	if (mbedtls_md_setup(md_ctx, md_info, 1) == MBEDTLS_ERR_MD_ALLOC_FAILED) {
		OT_LOG(LOG_ERR, "No memory for context");
		mbedtls_md_free(md_ctx);
		TEE_Free(md_ctx);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	if (mbedtls_md_starts(md_ctx)) {
		OT_LOG(LOG_ERR, "Invalid params");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	operation->ctx = (void *)md_ctx;
	return TEE_SUCCESS;
}

static void do_md_update(TEE_OperationHandle operation, uint8_t *chunk, uint32_t chunkSize)
{
	if (mbedtls_md_update((mbedtls_md_context_t *)operation->ctx, chunk, chunkSize)) {
		OT_LOG(LOG_ERR, "MD Update failed, invaid data");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}
}

static void do_md_final(TEE_OperationHandle operation, uint8_t *result, uint32_t *result_len)
{
	mbedtls_md_context_t *md_ctx;
	uint32_t size;

	md_ctx = (mbedtls_md_context_t *)operation->ctx;

	size = mbedtls_md_get_size(md_ctx->md_info);

	if (size > *result_len) {
		OT_LOG(LOG_ERR, "Invalid buffer size");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (mbedtls_md_finish(md_ctx, result)) {
		OT_LOG(LOG_ERR, "Bad paramaters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	*result_len = size;
}

/*
 * Crypto digest header functions
 */

TEE_Result init_gp_digest(TEE_OperationHandle operation, uint32_t algorithm)
{
	TEE_Result ret = TEE_SUCCESS;
	operation->operation_info.algorithm = algorithm;

	switch (algorithm) {
	case TEE_ALG_MD5:
	case TEE_ALG_SHA1:
	case TEE_ALG_SHA224:
	case TEE_ALG_SHA256:
	case TEE_ALG_SHA384:
	case TEE_ALG_SHA512:
		ret = do_md_init(operation);
		break;
	default:
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	operation->operation_info.digestLength = get_alg_hash_lenght(algorithm);
	operation->operation_info.handleState |= TEE_HANDLE_FLAG_INITIALIZED;

	return ret;
}

void free_gp_digest(TEE_OperationHandle operation)
{
	mbedtls_md_free((mbedtls_md_context_t *)operation->ctx);
	TEE_Free(operation->ctx);
	operation->ctx = NULL;
}


/*
 * GP TEE Core API functions
 */

void TEE_DigestUpdate(TEE_OperationHandle operation, void *chunk, uint32_t chunkSize)
{
	if (operation == NULL || (chunkSize > 0 && chunk == NULL))
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (operation->operation_info.operationClass != TEE_OPERATION_DIGEST ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED))
		TEE_Panic(TEE_ERROR_BAD_STATE);

	do_md_update(operation, (uint8_t *)chunk, chunkSize);

	operation->operation_info.operationState = TEE_OPERATION_STATE_ACTIVE;
}

TEE_Result TEE_DigestDoFinal(TEE_OperationHandle operation, void *chunk,
			     uint32_t chunkLen, void *hash, uint32_t *hashLen)
{
	if (operation == NULL || hash == NULL || hashLen == NULL || (chunkLen > 0 && chunk == NULL))
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (operation->operation_info.operationClass != TEE_OPERATION_DIGEST ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED))
		TEE_Panic(TEE_ERROR_BAD_STATE);

	if (operation->operation_info.digestLength > *hashLen)
		return TEE_ERROR_SHORT_BUFFER;

	if (chunk != NULL)
		do_md_update(operation, (uint8_t *)chunk, chunkLen);

	do_md_final(operation, (uint8_t *)hash, hashLen);

	*hashLen = operation->operation_info.digestLength;

	/* prepare the context to be reused if required */
	mbedtls_md_starts((mbedtls_md_context_t *)operation->ctx);
	TEE_ResetOperation(operation);

	return TEE_SUCCESS;
}
