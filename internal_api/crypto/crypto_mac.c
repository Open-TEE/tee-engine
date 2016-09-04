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

#include <stdlib.h>

#include "tee_crypto_api.h"
#include "tee_data_types.h"
#include "tee_panic.h"
#include "tee_memory.h"
#include "crypto_digest.h"
#include "crypto_utils.h"
#include "operation_handle.h"
#include "tee_logging.h"
#include "storage/object_handle.h"
#include "storage/storage_utils.h"

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

	md_ctx = (mbedtls_md_context_t *)calloc(1, sizeof(mbedtls_md_context_t));
	if (md_ctx == NULL) {
		OT_LOG(LOG_ERR, "No memory for context");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	mbedtls_md_init(md_ctx);

	if (mbedtls_md_setup(md_ctx, md_info, 1) == MBEDTLS_ERR_MD_ALLOC_FAILED) {
		OT_LOG(LOG_ERR, "No memory for context");
		mbedtls_md_free(md_ctx);
		free(md_ctx);
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	
	operation->operation_info.digestLength =
		get_alg_hash_lenght(operation->operation_info.algorithm);

	operation->ctx.md.ctx = (void *)md_ctx;
	return TEE_SUCCESS;
}

static void do_hmac_set_key(TEE_OperationHandle operation)
{
	int rv_mbedtls;
	
	rv_mbedtls = mbedtls_md_hmac_starts((mbedtls_md_context_t *)operation->ctx.md.ctx,
					    operation->ctx.md.key,
					    operation->key_data->key_lenght);
	
	if (rv_mbedtls) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG(LOG_ERR, "Error: internal crypto (MAC)");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}
}

static void do_hmac_update(TEE_OperationHandle operation,
			   uint8_t *chunk, size_t chunkSize)
{
	int rv_mbedtls;

	rv_mbedtls = mbedtls_md_hmac_update((mbedtls_md_context_t *)operation->ctx.md.ctx,
					    chunk, chunkSize);
	if (rv_mbedtls) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG(LOG_ERR, "Error: internal crypto (MAC)");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}
}

static void do_hmac_final(TEE_OperationHandle operation, uint8_t *result, size_t *result_len)
{
	mbedtls_md_context_t *md_ctx;
	uint32_t size;

	md_ctx = (mbedtls_md_context_t *)operation->ctx.md.ctx;

	size = mbedtls_md_get_size(md_ctx->private_md_info);

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

static void is_mac_alg_supported(TEE_OperationHandle operation)
{
	switch (operation->operation_info.algorithm) {
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		return;

	default:
		OT_LOG_ERR("Not supported algoritm [%u]", operation->operation_info.algorithm);
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}
}

/*
 * Crypto mac header functions
 */

TEE_Result mac_gp_init(TEE_OperationHandle operation)
{
	is_mac_alg_supported(operation);
	return do_hmac_init(operation);
}

void free_gp_mac(TEE_OperationHandle operation)
{
	is_mac_alg_supported(operation);
	mbedtls_md_free((mbedtls_md_context_t *)operation->ctx.md.ctx);
	free(operation->ctx.md.ctx);
	operation->ctx.md.ctx = NULL;
}

void reset_gp_mac(TEE_OperationHandle operation)
{
	is_mac_alg_supported(operation);
	mbedtls_md_hmac_reset((mbedtls_md_context_t *)operation->ctx.md.ctx);
}

void assign_key_mac(TEE_OperationHandle operation, TEE_ObjectHandle key)
{
	TEE_Attribute *sec_attr = NULL;

	sec_attr = (TEE_Attribute *)get_attr_from_attrArr(TEE_ATTR_SECRET_VALUE,
							  key->key->gp_attrs.attrs,
							  key->key->gp_attrs.attrs_count);
	if (sec_attr == NULL) {
		OT_LOG(LOG_ERR, "TEE_ATTR_SECRET_VALUE not found");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	operation->ctx.md.key = sec_attr->content.ref.buffer;
}

/*
 * GP TEE Core API functions
 */
void TEE_MACInit(TEE_OperationHandle operation,
		 void *IV, size_t IVLen)
{
	(void)IV;
	(void)IVLen;

	if (operation == NULL) {
		OT_LOG_ERR("TEE_MACInit panics due opertion NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.operationClass != TEE_OPERATION_MAC) {
		OT_LOG_ERR("TEE_MACInit panics due operation class not TEE_OPERATION_MAC");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.mode != TEE_MODE_MAC) {
		OT_LOG_ERR("TEE_MACInit panics due operation mode not TEE_MODE_MAC");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED) {
		OT_LOG_ERR("TEE_MACInit panics due operation not initialized");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		OT_LOG_ERR("TEE_MACInit panics due operation key is not set");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}
	
	if (operation->operation_info.operationState == TEE_OPERATION_STATE_ACTIVE)
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

void TEE_MACUpdate(TEE_OperationHandle operation,
		   void *chunk, size_t chunkSize)
{
	if (operation == NULL) {
		OT_LOG_ERR("TEE_MACUpdate panics due operation NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (chunk == NULL) {
		OT_LOG_ERR("TEE_MACUpdate panics due chunk NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.operationClass != TEE_OPERATION_MAC) {
		OT_LOG_ERR("TEE_MACUpdate panics due operation class not TEE_OPERATION_MAC");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.operationState != TEE_OPERATION_STATE_ACTIVE) {
		OT_LOG_ERR("TEE_MACUpdate panics due operation state not active");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.mode != TEE_MODE_MAC) {
		OT_LOG_ERR("TEE_MACUpdate panics due operation mode not TEE_MODE_MAC");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED)) {
		OT_LOG_ERR("TEE_MACUpdate panics due operation not initialized");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		OT_LOG_ERR("TEE_MACUpdate panics due operation key is not set");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

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

TEE_Result TEE_MACComputeFinal(TEE_OperationHandle operation,
			       void *message, size_t messageLen,
			       void *mac, size_t *macLen)
{
	if (operation == NULL) {
		OT_LOG_ERR("TEE_MACComputeFinal panics due operation NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (macLen == NULL) {
		OT_LOG_ERR("TEE_MACComputeFinal panics due macLen NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (mac == NULL) {
		OT_LOG_ERR("TEE_MACComputeFinal panics due mac NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.operationClass != TEE_OPERATION_MAC) {
		OT_LOG_ERR("TEE_MACComputeFinal panics due operation class not TEE_OPERATION_MAC");
		TEE_Panic(TEE_ERROR_BAD_STATE);
	} else if (operation->operation_info.operationState != TEE_OPERATION_STATE_ACTIVE) {
		OT_LOG_ERR("TEE_MACComputeFinal panics due operation is not active");
		TEE_Panic(TEE_ERROR_BAD_STATE);
	} else if (operation->operation_info.mode != TEE_MODE_MAC) {
		OT_LOG_ERR("TEE_MACComputeFinal panics due operation mode not TEE_MODE_MAC");
		TEE_Panic(TEE_ERROR_BAD_STATE);
	} else if (!(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED)) {
		OT_LOG_ERR("TEE_MACComputeFinal panics due operation not initialized");
		TEE_Panic(TEE_ERROR_BAD_STATE);
	} else if (!(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		OT_LOG_ERR("TEE_MACComputeFinal panics due operation key is not set");
		TEE_Panic(TEE_ERROR_BAD_STATE);
	}

	if (operation->operation_info.digestLength > *macLen) {
		return TEE_ERROR_SHORT_BUFFER;
	}
	
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

	//*macLen = operation->operation_info.digestLength;
	//prepare to reuse the context if required
	
	TEE_ResetOperation(operation);

	return TEE_SUCCESS;
}

TEE_Result TEE_MACCompareFinal(TEE_OperationHandle operation,
			       void *message, size_t messageLen,
			       void *mac, size_t macLen)
{
	// Reserved according to the biggest mac output (HMAC_SHA512)
	char computed_mac[BIGGEST_MAC_OUTPUT] = {0};
	size_t computed_mac_len = BIGGEST_MAC_OUTPUT;
	TEE_Result ret = TEE_SUCCESS;

	ret = TEE_MACComputeFinal(operation, message, messageLen, computed_mac, &computed_mac_len);
	if (ret != TEE_SUCCESS)
		TEE_Panic(TEE_ERROR_GENERIC);

	if (macLen > computed_mac_len || TEE_MemCompare(mac, computed_mac, macLen) != 0)
		ret = TEE_ERROR_MAC_INVALID;

	TEE_ResetOperation(operation);
	
	return ret;
}
