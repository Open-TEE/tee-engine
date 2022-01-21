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

#include "tee_crypto_api.h"
#include "tee_panic.h"
#include "tee_memory.h"

#include "crypto_utils.h"
#include "storage/storage_utils.h"
#include "crypto_cipher.h"
#include "operation_handle.h"
#include "storage/object_handle.h"

#include "tee_logging.h"

#include <mbedtls/cipher.h>
#include <stdlib.h>

static mbedtls_cipher_type_t gp_cipher_to_mbedtls(TEE_OperationHandle operation)
{
	uint32_t key_size = BYTES_TO_BITS(operation->key_data->key_lenght);

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

static TEE_Result valid_iv_len(TEE_OperationHandle operation, size_t ivlen)
{
	switch (operation->operation_info.algorithm) {

	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_AES_CTR:
		if (ivlen != 16) {
			OT_LOG_ERR("Error: Algorithm (TEE_ALG_AES_CTR, TEE_ALG_AES_CBC_NOPAD) requires 16 bytes IV");
			return TEE_ERROR_BAD_PARAMETERS;
		}

		break;
	default:
		//Should never end up here
		OT_LOG_ERR("Not supported algorithm [%u]", operation->operation_info.algorithm);
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	return TEE_SUCCESS;
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
	
	operation->ctx.cipher.ctx = cipher_ctx;

	return TEE_SUCCESS;

out_err_2:
	mbedtls_cipher_free(cipher_ctx);
	free(cipher_ctx);
out_err_1:
	return res;
}

void free_gp_cipher(TEE_OperationHandle operation)
{
	mbedtls_cipher_context_t *cipher_ctx = (mbedtls_cipher_context_t *)operation->ctx.cipher.ctx;

	mbedtls_cipher_free(cipher_ctx);
	free(cipher_ctx);
	operation->ctx.cipher.ctx = NULL;
}

void reset_gp_cipher(TEE_OperationHandle operation)
{
	mbedtls_cipher_reset((mbedtls_cipher_context_t *)operation->ctx.cipher.ctx);
}

void assign_key_cipher(TEE_OperationHandle operation, TEE_ObjectHandle key)
{
	TEE_Attribute *sec_attr = NULL;

	sec_attr = get_attr_from_attrArr(TEE_ATTR_SECRET_VALUE,
					 key->key->gp_attrs.attrs,
					 key->key->gp_attrs.attrs_count);
	if (sec_attr == NULL) {
		OT_LOG(LOG_ERR, "TEE_ATTR_SECRET_VALUE not found");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	operation->ctx.cipher.key = sec_attr->content.ref.buffer;
}

/*
 * GP TEE Core API functions
 */
void TEE_CipherInit(TEE_OperationHandle operation,
		    void *IV, size_t IVLen)
{
	mbedtls_cipher_context_t *cipher_ctx;
	mbedtls_operation_t mbed_op;
	int rv_mbedtls;
	TEE_Result rv_gp;
	
	if (operation == NULL) {
		OT_LOG_ERR("TEE_CipherInit panics due operation NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.operationClass != TEE_OPERATION_CIPHER) {
		OT_LOG_ERR("TEE_CipherInit panics due operation class not TEE_OPERATION_CIPHER");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED) {
		OT_LOG_ERR("TEE_CipherInit panics due operation not initialized");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		OT_LOG_ERR("TEE_CipherInit panics due operation key is not set");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (valid_iv_len(operation, IVLen)) {
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}
	
	if (operation->operation_info.handleState == TEE_OPERATION_STATE_ACTIVE) {
		TEE_ResetOperation(operation);
	}

	rv_gp = init_gp_cipher(operation);
	if (rv_gp != TEE_SUCCESS) {
		//NOTE: breaks GP compatibility. Might fail with out of memory.
		TEE_Panic(rv_gp);
	}
	
	cipher_ctx = (mbedtls_cipher_context_t *)operation->ctx.cipher.ctx;
	mbed_op = (operation->operation_info.mode == TEE_MODE_ENCRYPT) ?
			  MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT;
	
	rv_mbedtls = mbedtls_cipher_setkey(cipher_ctx, operation->ctx.cipher.key,
					   keysize_in_bits(operation->key_data->key_lenght), mbed_op);
	if (rv_mbedtls) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG(LOG_ERR, "TEE_CipherInit (internal crypto error) panics due unable set key");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	rv_mbedtls = mbedtls_cipher_set_iv(cipher_ctx, (uint8_t *)IV, IVLen);
	if (rv_mbedtls) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG(LOG_ERR, "TEE_CipherInit (internal crypto error) panics due unable set IV");
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
			OT_LOG(LOG_ERR, "TEE_CipherInit panics due not supported algorithm (algorithm[%u])",
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

TEE_Result TEE_CipherUpdate(TEE_OperationHandle operation,
			    void *srcData, size_t srcLen,
			    void *destData, size_t *destLen)
{
	int rv_mbedtls;
	
	if (operation == NULL) {
		OT_LOG_ERR("TEE_CipherUpdate panics due operation NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (srcData == NULL) {
		OT_LOG_ERR("TEE_CipherUpdate panics due srcData NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (destData == NULL) {
		OT_LOG_ERR("TEE_CipherUpdate panics due destData NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (destLen == NULL) {
		OT_LOG_ERR("TEE_CipherUpdate panics due destLen NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.operationClass != TEE_OPERATION_CIPHER) {
		OT_LOG_ERR("TEE_CipherUpdate panics due operation class not TEE_OPERATION_CIPHER");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED)) {
		OT_LOG_ERR("TEE_CipherUpdate panics due operation not initialized");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		OT_LOG_ERR("TEE_CipherUpdate panics due operation key not set");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.operationState != TEE_OPERATION_STATE_ACTIVE) {
		OT_LOG_ERR("TEE_CipherUpdate panics due operation not active state");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (srcLen > *destLen) {
		OT_LOG_ERR("TEE_CipherUpdate: srcLen bigger than destLen (TEE_ERROR_SHORT_BUFFER)");
		return TEE_ERROR_SHORT_BUFFER;
	}

	rv_mbedtls = mbedtls_cipher_update((mbedtls_cipher_context_t *)operation->ctx.cipher.ctx,
					   (uint8_t *)srcData, srcLen,
					   (uint8_t *)destData, destLen);
	if (rv_mbedtls) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG(LOG_ERR,"Error: Internal cipher error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

TEE_Result TEE_CipherDoFinal(TEE_OperationHandle operation,
			     void *srcData, size_t srcLen,
			     void *destData, size_t *destLen)
{
	TEE_Result ret = TEE_SUCCESS;
	int mbedret;
	size_t updateDestLen = 0, finalDestLen = 0;

	//TODO: Check destlen buffer size!!

	if (operation == NULL) {
		OT_LOG_ERR("TEE_CipherDoFinal panics due operation NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (destData == NULL) {
		OT_LOG_ERR("TEE_CipherDoFinal panics due destData NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (destLen == NULL) {
		OT_LOG_ERR("TEE_CipherDoFinal panics due destLen NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (srcLen > 0 && srcData == NULL) {
		OT_LOG_ERR("TEE_CipherDoFinal panics due scrLen is non zero, but srcData NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.operationClass != TEE_OPERATION_CIPHER) {
		OT_LOG_ERR("TEE_CipherDoFinal panics due operation class not TEE_OPERATION_CIPHER");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED)) {
		OT_LOG_ERR("TEE_CipherDoFinal panics due operation not initialized");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		OT_LOG_ERR("TEE_CipherDoFinal panics due operation key not set");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.operationState != TEE_OPERATION_STATE_ACTIVE) {
		OT_LOG_ERR("TEE_CipherDoFinal panics due operation state is not active");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (srcData != NULL) {
		updateDestLen = *destLen;
		
		ret = TEE_CipherUpdate(operation, srcData, srcLen, destData, &updateDestLen);
		if (ret != TEE_SUCCESS) {
			return ret;
		}

		//TODO: Implement underflow check
		finalDestLen = *destLen - updateDestLen;
		destData = (uint8_t *)destData + updateDestLen;
	} else {
		finalDestLen = *destLen;
	}

	//TODO: Enough space for padding??
	
	mbedret = mbedtls_cipher_finish((mbedtls_cipher_context_t *)operation->ctx.cipher.ctx,
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

	return ret;
}
