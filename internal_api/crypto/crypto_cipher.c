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

#include "crypto_cipher.h"
#include "operation_handle.h"

#include "opentee_storage_common.h"
#include "tee_logging.h"

#include <mbedtls/cipher.h>

static mbedtls_cipher_type_t gp_cipher_to_mbedtls(TEE_OperationHandle operation)
{
	uint32_t key_size = operation->operation_info.maxKeySize;

	switch (operation->operation_info.algorithm) {
	case TEE_ALG_AES_ECB_NOPAD:
		switch (key_size) {
		case 128:
			return MBEDTLS_CIPHER_AES_128_ECB;
		case 192:
			return MBEDTLS_CIPHER_AES_192_ECB;
		case 256:
			return MBEDTLS_CIPHER_AES_256_ECB;
		default:
			OT_LOG(LOG_ERR, "Unknown key size");
		}
		return MBEDTLS_CIPHER_NONE;

	case TEE_ALG_AES_CBC_NOPAD:
		switch (key_size) {
		case 128:
			return MBEDTLS_CIPHER_AES_128_CBC;
		case 192:
			return MBEDTLS_CIPHER_AES_192_CBC;
		case 256:
			return MBEDTLS_CIPHER_AES_256_CBC;
		default:
			OT_LOG(LOG_ERR, "Unknown key size");
		}
		return MBEDTLS_CIPHER_NONE;

	case TEE_ALG_AES_CTR:
		switch (key_size) {
		case 128:
			return MBEDTLS_CIPHER_AES_128_CTR;
		case 192:
			return MBEDTLS_CIPHER_AES_192_CTR;
		case 256:
			return MBEDTLS_CIPHER_AES_256_CTR;
		default:
			OT_LOG(LOG_ERR, "Unknown key size");
		}
		return MBEDTLS_CIPHER_NONE;

	case TEE_ALG_AES_CCM:
		switch (key_size) {
		case 128:
			return MBEDTLS_CIPHER_AES_128_CCM;
		case 192:
			return MBEDTLS_CIPHER_AES_192_CCM;
		case 256:
			return MBEDTLS_CIPHER_AES_256_CCM;
		default:
			OT_LOG(LOG_ERR, "Unknown key size");
		}
		return MBEDTLS_CIPHER_NONE;

	case TEE_ALG_AES_GCM:
		switch (key_size) {
		case 128:
			return MBEDTLS_CIPHER_AES_128_GCM;
		case 192:
			return MBEDTLS_CIPHER_AES_192_GCM;
		case 256:
			return MBEDTLS_CIPHER_AES_256_GCM;
		default:
			OT_LOG(LOG_ERR, "Unknown key size");
		}
		return MBEDTLS_CIPHER_NONE;

	case TEE_ALG_DES_ECB_NOPAD:
		return MBEDTLS_CIPHER_DES_ECB;
	case TEE_ALG_DES_CBC_NOPAD:
		return MBEDTLS_CIPHER_DES_CBC;
	case TEE_ALG_DES3_ECB_NOPAD:
		return MBEDTLS_CIPHER_DES_EDE_ECB;
	case TEE_ALG_DES3_CBC_NOPAD:
		return MBEDTLS_CIPHER_DES_EDE_CBC;
	default:
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	return MBEDTLS_CIPHER_NONE;
}

/*
 * Crypto cipher header functions
 */

TEE_Result init_gp_cipher(TEE_OperationHandle operation)
{
	mbedtls_cipher_context_t *cipher_ctx;
	const mbedtls_cipher_info_t *cipher_info;
	int ret;
	TEE_Result res = TEE_ERROR_OUT_OF_MEMORY;

	cipher_info = mbedtls_cipher_info_from_type(gp_cipher_to_mbedtls(operation));

	cipher_ctx = (mbedtls_cipher_context_t *)TEE_Malloc(sizeof(mbedtls_cipher_context_t), 1);
	if (cipher_ctx == NULL)
		goto out_err_1;

	mbedtls_cipher_init(cipher_ctx);
	
	ret = mbedtls_cipher_setup(cipher_ctx, cipher_info);
	if (ret == MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA) {
		OT_LOG(LOG_ERR, "mbedtls_cipher_setup failed bad input");
		res = TEE_ERROR_BAD_PARAMETERS;
		 goto out_err_2;
	} else if (ret == MBEDTLS_ERR_CIPHER_ALLOC_FAILED) {
		OT_LOG(LOG_ERR, "mbedtls_cipher_setup out of memory");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out_err_2;
	}
	
	operation->ctx = cipher_ctx;

	return TEE_SUCCESS;

out_err_2:
	mbedtls_cipher_free(cipher_ctx);
	TEE_Free(cipher_ctx);
out_err_1:
	return res;
}

void free_gp_cipher(TEE_OperationHandle operation)
{
	mbedtls_cipher_context_t *cipher_ctx = (mbedtls_cipher_context_t *)operation->ctx;

	mbedtls_cipher_free(cipher_ctx);
	free(cipher_ctx);
	operation->ctx = NULL;
}

void reset_gp_cipher(TEE_OperationHandle operation)
{
	mbedtls_cipher_reset((mbedtls_cipher_context_t *)operation->ctx);
	operation->operation_info.operationState = TEE_OPERATION_STATE_INITIAL;
	operation->operation_info.handleState &= TEE_HANDLE_FLAG_INITIALIZED;
}


/*
 * GP TEE Core API functions
 */
void TEE_CipherInit(TEE_OperationHandle operation, void *IV, uint32_t IVLen)
{
	mbedtls_cipher_context_t *cipher_ctx;
	mbedtls_operation_t mbed_op;

	if (operation == NULL) {
		OT_LOG_ERR("TEE_CipherInit panicking due operation handle NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}
	
	if (operation->operation_info.operationClass != TEE_OPERATION_CIPHER ||
	    operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET))
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (operation->operation_info.handleState == TEE_OPERATION_STATE_ACTIVE)
		TEE_ResetOperation(operation);

	cipher_ctx = (mbedtls_cipher_context_t *)operation->ctx;
	mbed_op = (operation->operation_info.mode == TEE_MODE_ENCRYPT) ?
			  MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT;

	if (mbedtls_cipher_setkey(cipher_ctx, operation->key_data->key.secret.key,
				  keysize_in_bits(operation->key_data->key_lenght), mbed_op)) {
		OT_LOG(LOG_ERR, "TEE_CipherInit panicking due unable set key");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (mbedtls_cipher_set_iv(cipher_ctx, (uint8_t *)IV, IVLen)) {
		OT_LOG(LOG_ERR, "TEE_CipherInit panicking due unable set IV");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	switch (operation->operation_info.algorithm) {
	case TEE_ALG_AES_ECB_NOPAD:
	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES_CBC_NOPAD:
	case TEE_ALG_DES3_ECB_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
		if (mbedtls_cipher_set_padding_mode(cipher_ctx, MBEDTLS_PADDING_NONE)) {
			OT_LOG(LOG_ERR, "TEE_CipherInit panicking due not supported algorithm (algorithm[%u])",
			       operation->operation_info.algorithm);
			TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
		}
		break;
	default:
		break;
	}

	operation->operation_info.operationState = TEE_OPERATION_STATE_ACTIVE;
	operation->operation_info.handleState |= TEE_HANDLE_FLAG_INITIALIZED;
}

TEE_Result TEE_CipherUpdate(TEE_OperationHandle operation, void *srcData,
			    uint32_t srcLen, void *destData, uint32_t *destLen)
{
	size_t destLen2;
	
	if (operation == NULL || srcData == NULL || destData == NULL || destLen == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (operation->operation_info.operationClass != TEE_OPERATION_CIPHER ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED) ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET) ||
	    operation->operation_info.operationState != TEE_OPERATION_STATE_ACTIVE)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	destLen2 = *destLen;
	
	if (mbedtls_cipher_update((mbedtls_cipher_context_t *)operation->ctx, (uint8_t *)srcData,
				  srcLen, (uint8_t *)destData, &destLen2)) {
		OT_LOG(LOG_ERR,"Update error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	*destLen = destLen2;
	
	return TEE_SUCCESS;
}

TEE_Result TEE_CipherDoFinal(TEE_OperationHandle operation, void *srcData,
			     uint32_t srcLen, void *destData, uint32_t *destLen)
{
	TEE_Result ret = TEE_SUCCESS;
	int mbedret;
	size_t updateDestLen = 0, finalDestLen = 0, destLen2;
	void *leftDestData;

	//TODO: Check destlen buffer size!!

	if (operation == NULL || destData == NULL || destLen == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (srcLen > 0 && srcData == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (operation->operation_info.operationClass != TEE_OPERATION_CIPHER ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED) ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET) ||
	    operation->operation_info.operationState != TEE_OPERATION_STATE_ACTIVE)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	
	if (srcData != NULL) {
		updateDestLen = *destLen;
		
		ret = TEE_CipherUpdate(operation, srcData, srcLen, destData, &updateDestLen);
		if (ret != TEE_SUCCESS) {
			return ret;
		}

		//TODO: Implement underflow check
		finalDestLen = *destLen - updateDestLen;
		destData = (uint8_t)destData + updateDestLen;
	} else {
		finalDestLen = *destLen;
	}

	//TODO: Enough space for padding??
	mbedret = mbedtls_cipher_finish((mbedtls_cipher_context_t *)operation->ctx,
					(uint8_t *)destData, &finalDestLen);
	if (mbedret == MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA) {
		return TEE_ERROR_BAD_PARAMETERS;
	} else if (mbedret == MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED) {
		return TEE_ERROR_BAD_PARAMETERS;
	} else if (mbedret == MBEDTLS_ERR_CIPHER_INVALID_PADDING) {
		return TEE_ERROR_BAD_STATE;
	}

	//TODO: Check if overflow from 8byte to 4byte
	*destLen = updateDestLen + finalDestLen;

	TEE_ResetOperation(operation);

	operation->operation_info.operationState |= TEE_OPERATION_STATE_INITIAL;

	return ret;
}
