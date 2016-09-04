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

//#include <string.h>

#include "../tee_crypto_api.h"
#include "../tee_data_types.h"
#include "../tee_panic.h"
#include "../tee_memory.h"
#include "crypto_digest.h"
#include "crypto_utils.h"
#include "operation_handle.h"
#include "tee_logging.h"

#include <mbedtls/md.h>

#define BIGGEST_MAC_OUTPUT 64 /* HMAC_SHA512 */

static mbedtls_md_type_t gp_mac_to_mbedtls(uint32_t mac_type)
{
	switch (mac_type) {
	case TEE_ALG_HMAC_MD5:
		return MBEDTLS_MD_MD5;
	case TEE_ALG_HMAC_SHA1:
		return MBEDTLS_MD_SHA1;
	case TEE_ALG_HMAC_SHA224:
		return MBEDTLS_MD_SHA224;
	case TEE_ALG_HMAC_SHA256:
		return MBEDTLS_MD_SHA256;
	case TEE_ALG_HMAC_SHA384:
		return MBEDTLS_MD_SHA384;
	case TEE_ALG_HMAC_SHA512:
		return MBEDTLS_MD_SHA512;
	default:
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	return MBEDTLS_MD_NONE;
}

static TEE_Result do_hmac_init(TEE_OperationHandle operation)
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

	operation->ctx = (void *)md_ctx;
	return TEE_SUCCESS;
}

static void do_hmac_set_key(TEE_OperationHandle operation)
{
	if (mbedtls_md_hmac_starts((mbedtls_md_context_t *)operation->ctx,
				   operation->key_data->key.secret.key,
				   operation->key_data->key_lenght)) {
		OT_LOG(LOG_ERR, "Invalid params");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}
}

static void do_hmac_update(TEE_OperationHandle operation, uint8_t *chunk, uint32_t chunkSize)
{
	if (mbedtls_md_hmac_update((mbedtls_md_context_t *)operation->ctx, chunk, chunkSize)) {
		OT_LOG(LOG_ERR, "HMAC Update failed, invaid data");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}
}

static void do_hmac_final(TEE_OperationHandle operation, uint8_t *result, uint32_t *result_len)
{
	mbedtls_md_context_t *md_ctx;
	uint32_t size;

	md_ctx = (mbedtls_md_context_t *)operation->ctx;

	size = mbedtls_md_get_size(md_ctx->md_info);

	if (size > *result_len) {
		OT_LOG(LOG_ERR, "Invalid buffer size");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (mbedtls_md_hmac_finish(md_ctx, result)) {
		OT_LOG(LOG_ERR, "Bad paramaters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	*result_len = size;
}

/*
 * Crypto mac header functions
 */

TEE_Result mac_gp_init(TEE_OperationHandle operation)
{
	switch (operation->operation_info.algorithm) {
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		return do_hmac_init(operation);

	default:
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	return TEE_SUCCESS;
}

void free_gp_mac(TEE_OperationHandle operation)
{
	mbedtls_md_free((mbedtls_md_context_t *)operation->ctx);
	TEE_Free(operation->ctx);
	operation->ctx = NULL;
}

/*
 * GP TEE Core API functions
 */
void TEE_MACInit(TEE_OperationHandle operation, void *IV, uint32_t IVLen)
{
	(void)IV;
	(void)IVLen;

	if (operation == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (operation->operation_info.operationClass != TEE_OPERATION_MAC ||
	    operation->operation_info.mode != TEE_MODE_MAC ||
	    operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET))
		TEE_Panic(TEE_ERROR_BAD_STATE);

	if (operation->operation_info.handleState == TEE_OPERATION_STATE_ACTIVE)
		TEE_ResetOperation(operation);

	switch (operation->operation_info.algorithm) {
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		do_hmac_set_key(operation);
		break;

	default:
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	operation->operation_info.operationState = TEE_OPERATION_STATE_ACTIVE;
	operation->operation_info.handleState |= TEE_HANDLE_FLAG_INITIALIZED;
}

void TEE_MACUpdate(TEE_OperationHandle operation, void *chunk, uint32_t chunkSize)
{
	if (operation == NULL || chunk == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (operation->operation_info.operationClass != TEE_OPERATION_MAC ||
	    operation->operation_info.operationState != TEE_OPERATION_STATE_ACTIVE ||
	    operation->operation_info.mode != TEE_MODE_MAC ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED) ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET))
		TEE_Panic(TEE_ERROR_BAD_STATE);

	switch (operation->operation_info.algorithm) {
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		do_hmac_update(operation, (uint8_t *)chunk, chunkSize);
		break;

	default:
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}
}

TEE_Result TEE_MACComputeFinal(TEE_OperationHandle operation, void *message,
			       uint32_t messageLen, void *mac, uint32_t *macLen)
{
	if (operation == NULL || macLen == NULL || mac == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (operation->operation_info.operationClass != TEE_OPERATION_MAC ||
	    operation->operation_info.operationState != TEE_OPERATION_STATE_ACTIVE ||
	    operation->operation_info.mode != TEE_MODE_MAC ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED) ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET))
		TEE_Panic(TEE_ERROR_BAD_STATE);

	if (operation->operation_info.digestLength > *macLen)
		return TEE_ERROR_SHORT_BUFFER;

	switch (operation->operation_info.algorithm) {
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		if (message != NULL)
			do_hmac_update(operation, (uint8_t *)message, messageLen);
		do_hmac_final(operation, (uint8_t *)mac, macLen);
		break;

	default:
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	*macLen = operation->operation_info.digestLength;

	/*prepare to reuse the context if required */
	mbedtls_md_hmac_reset((mbedtls_md_context_t *)operation->ctx);
	TEE_ResetOperation(operation);

	return TEE_SUCCESS;
}

TEE_Result TEE_MACCompareFinal(TEE_OperationHandle operation, void *message,
			       uint32_t messageLen, void *mac, uint32_t macLen)
{
	/* Reserved according to the biggest mac output (HMAC_SHA512) */
	char computed_mac[BIGGEST_MAC_OUTPUT] = {0};
	uint32_t computed_mac_len = BIGGEST_MAC_OUTPUT;
	TEE_Result ret = TEE_SUCCESS;

	ret = TEE_MACComputeFinal(operation, message, messageLen, computed_mac, &computed_mac_len);
	if (ret != TEE_SUCCESS)
		TEE_Panic(TEE_ERROR_GENERIC);

	if (macLen > computed_mac_len || TEE_MemCompare(mac, computed_mac, macLen) != 0)
		ret = TEE_ERROR_MAC_INVALID;

	return ret;
}
