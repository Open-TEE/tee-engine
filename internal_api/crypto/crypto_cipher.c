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
#include "crypto_cipher.h"
#include "operation_handle.h"
#include "../tee_memory.h"

#define MAX_CIPHER_IV_LENGTH 16 /* 16 == AES CBC */

struct cipher_ctx {
	void *ctx;
	void *IV;
	uint32_t IV_length;

	/* AES spesific <-- Obsolite
	AES_OPERATION aes_operation;
	AES_KEY_TYPE aes_key_type;
	*/
};





static TEE_Result do_aes_cbc(TEE_OperationHandle operation,
			     void *srcData,
			     uint32_t srcLen,
			     void *destData,
			     uint32_t *destLen)
{
	struct cipher_ctx *cipher_ctx = (struct cipher_ctx *)operation->ctx;

	if (operation->operation_info.operationClass != TEE_OPERATION_CIPHER ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED) ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET) ||
	    operation->operation_info.operationState != TEE_OPERATION_STATE_ACTIVE)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	/* TEE_CipherDoFinal: AES CBC NOPAD no final part */
	if (srcData == NULL) {
		*destLen = 0;
		return TEE_SUCCESS;
	}

	/*Must be multiple of 16 */
	if (srcLen % 16)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (srcLen > *destLen)
		return TEE_ERROR_SHORT_BUFFER;

//	if (crypto_aes_cbc(cipher_ctx->aes_operation, cipher_ctx->aes_key_type,
//			   operation->key->key.secret.key, (uint8_t *)cipher_ctx->ctx,
//			   srcLen, (uint8_t *)srcData, (uint8_t *)destData) != OK)
//		TEE_Panic(TEE_ERROR_GENERIC);

	*destLen = srcLen;
	return TEE_SUCCESS;
}




/*
 * Crypto cipher header functions
 */

TEE_Result init_gp_cipher(TEE_OperationHandle operation,
			  uint32_t algorithm,
			  uint32_t mode)
{
	struct cipher_ctx *new_cipher_ctx;

	new_cipher_ctx = (struct cipher_ctx *)TEE_Malloc(sizeof(struct cipher_ctx), 1);
	if (new_cipher_ctx == NULL)
		goto out_of_mem_1;

	switch (algorithm) {
	case TEE_ALG_AES_CBC_NOPAD:

		new_cipher_ctx->ctx = TEE_Malloc(MAX_CIPHER_IV_LENGTH, 1);
		if (new_cipher_ctx->ctx == NULL)
			goto out_of_mem_2;

		new_cipher_ctx->IV = TEE_Malloc(MAX_CIPHER_IV_LENGTH, 1);
		if (new_cipher_ctx->IV == NULL)
			goto out_of_mem_3;

//		new_cipher_ctx->aes_operation = map_mode2AesOperation(mode);
		new_cipher_ctx->IV_length = MAX_CIPHER_IV_LENGTH;
		break;

	default:
		/* No action */
		break;
	}

	operation->ctx = new_cipher_ctx;

	return TEE_SUCCESS;

out_of_mem_3:
	free(new_cipher_ctx->ctx);
out_of_mem_2:
	free(new_cipher_ctx);
out_of_mem_1:
	return TEE_ERROR_OUT_OF_MEMORY;
}

void free_gp_cipher(TEE_OperationHandle operation)
{
	struct cipher_ctx *cipher_ctx = (struct cipher_ctx *)operation->ctx;

	free(cipher_ctx->ctx);
	free(cipher_ctx->IV);
	free(cipher_ctx);
}

void reset_gp_cipher(TEE_OperationHandle operation)
{
	struct cipher_ctx *cipher_ctx = (struct cipher_ctx *)operation->ctx;

	memcpy(cipher_ctx->ctx, cipher_ctx->IV, cipher_ctx->IV_length);
	operation->operation_info.operationState = TEE_OPERATION_STATE_INITIAL;
	operation->operation_info.handleState &= TEE_HANDLE_FLAG_INITIALIZED;
}






/*
 * GP TEE Core API functions
 */

void TEE_CipherInit(TEE_OperationHandle operation,
		    void *IV,
		    uint32_t IVLen)
{
	struct cipher_ctx *cipher_ctx;

	if (operation == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (operation->operation_info.operationClass != TEE_OPERATION_CIPHER ||
	    operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET))
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (operation->operation_info.handleState == TEE_OPERATION_STATE_ACTIVE)
		TEE_ResetOperation(operation);

	cipher_ctx = (struct cipher_ctx *)operation->ctx;

	/* Check IV */
	switch (operation->operation_info.algorithm) {
	case TEE_ALG_AES_CBC_NOPAD:
		/* Size of IV is 16 bytes. */
		if (IV == NULL || IVLen != 16)
			TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

//		cipher_ctx->aes_key_type = map_keySize2AesAlgortihm(operation->key->key_lenght);
		break;

	default:
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	cipher_ctx->IV_length = IVLen;
	memcpy(cipher_ctx->IV, IV, IVLen);
	memcpy(cipher_ctx->ctx, IV, IVLen);
	operation->operation_info.operationState = TEE_OPERATION_STATE_ACTIVE;
	operation->operation_info.handleState |= TEE_HANDLE_FLAG_INITIALIZED;
}

TEE_Result TEE_CipherUpdate(TEE_OperationHandle operation,
			    void *srcData,
			    uint32_t srcLen,
			    void *destData,
			    uint32_t *destLen)
{
	if (operation == NULL || srcData == NULL || destData == NULL || destLen == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	switch (operation->operation_info.algorithm) {
	case TEE_ALG_AES_CBC_NOPAD:
		return do_aes_cbc(operation, srcData, srcLen, destData, destLen);
	default:
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	return TEE_ERROR_GENERIC; /* For compiler, never reached */
}


TEE_Result TEE_CipherDoFinal(TEE_OperationHandle operation,
			     void *srcData,
			     uint32_t srcLen,
			     void *destData,
			     uint32_t *destLen)
{
	TEE_Result ret;

	if (operation == NULL || destData == NULL || destLen == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (srcLen > 0 && srcData == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	switch (operation->operation_info.algorithm) {
	case TEE_ALG_AES_CBC_NOPAD:
		ret = do_aes_cbc(operation, srcData, srcLen, destData, destLen);
		break;
	default:
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	if (ret == TEE_SUCCESS)
		TEE_ResetOperation(operation);

	return ret;
}
