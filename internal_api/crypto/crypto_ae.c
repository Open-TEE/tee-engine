/*****************************************************************************
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

#include <stddef.h>
#include <mbedtls/gcm.h>
#include <stdlib.h>

#include "operation_handle.h"
#include "tee_logging.h"
#include "crypto_utils.h"
#include "storage/object_handle.h"
#include "storage/storage_utils.h"
#include "tee_panic.h"

static TEE_Result valid_tag_len(size_t tagLen)
{
	switch (tagLen) {
	case 128:
	case 120:
	case 112:
	case 104:
	case 96:
		return TEE_SUCCESS;
	default:
		OT_LOG_ERR("Not supported tagLen (provided[%lu])", tagLen);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

static void is_alg_supported(TEE_OperationHandle operation)
{
	//OpenTEE internal sanity check
	if (operation->operation_info.algorithm != TEE_ALG_AES_GCM) {
		OT_LOG_ERR("Not supported algorithm (only TEE_ALG_AES_GCM)");
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}
}

static TEE_Result do_ae_final(TEE_OperationHandle operation,
			      void *srcData, size_t srcLen,
			      void *destData, size_t *destLen,
			      void *tag, size_t *tagLen)
{
	TEE_Result rv_gp = TEE_SUCCESS;
	unsigned char *destDataLeftStart;
	size_t destDataLeftLen = 0, finalOutputLen, initTagLen;
	int rv_mbedtls;
	
	if (operation == NULL) {
		OT_LOG_ERR("TEE_AE_FInal panics due operation NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.operationState != TEE_OPERATION_STATE_ACTIVE) {
		OT_LOG_ERR("TEE_AE_FInal panics due operation state needs to be TEE_OPERATION_STATE_ACTIVE");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		OT_LOG_ERR("TEE_AE_FInal panics due operation key is not set");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.operationClass != TEE_OPERATION_AE) {
		OT_LOG_ERR("TEE_AE_FInal panics due operation class not TEE_OPERATION_AE");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED)) {
		OT_LOG_ERR("TEE_AE_FInal panics due operation is NOT initialized");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (BITS_TO_BYTES(operation->operation_info.digestLength) > *tagLen) {
		OT_LOG_ERR("TEE_AE_FInal panics due tagLen not right (expected[%u], provided[%lu])",
			   BITS_TO_BYTES(operation->operation_info.digestLength), *tagLen);
	}

	is_alg_supported(operation);

	initTagLen = BITS_TO_BYTES(operation->operation_info.digestLength);
	
	if (destLen != NULL) {
		destDataLeftLen = *destLen;
	}
	
	if (srcData != NULL) {
		rv_gp = TEE_AEUpdate(operation, srcData, srcLen, destData, destLen);
	}
	
	if (rv_gp != TEE_SUCCESS) {
		return rv_gp;
	}

	if (destLen != NULL) {
		destDataLeftStart = (unsigned char *)((uint8_t *)destData + *destLen);
		destDataLeftLen -= *destLen;
	} else {
		destDataLeftStart = (unsigned char *)NULL;
		destDataLeftLen -= 0;
	}
	
	rv_mbedtls = mbedtls_gcm_finish(operation->ctx.gcm.ctx,
					destDataLeftStart, destDataLeftLen,
					&finalOutputLen,
					tag, initTagLen);
	if (rv_mbedtls) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG(LOG_ERR,"Error: Internal AE error (details print to syslog)");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (destLen != NULL) {
		*destLen = *destLen + finalOutputLen;
	}
	*tagLen = initTagLen;
	TEE_ResetOperation(operation);
	
	return rv_gp;
}

TEE_Result init_gp_ae(TEE_OperationHandle operation)
{
	operation->ctx.gcm.ctx = calloc(1, sizeof(mbedtls_gcm_context));
	if (operation->ctx.gcm.ctx == NULL) {
		OT_LOG_ERR("Out of memory");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	mbedtls_gcm_init(operation->ctx.gcm.ctx);
	return TEE_SUCCESS;
}

void free_gp_ae(TEE_OperationHandle operation)
{
	mbedtls_gcm_free(operation->ctx.gcm.ctx);
	free(operation->ctx.gcm.ctx);
}

void reset_gp_ae(TEE_OperationHandle operation)
{
	//Not sure about how to reset, because not reset function :/
	//TODO (NOTE): Breaks GP compatibility. Using malloc.

	free_gp_ae(operation);

	if (init_gp_ae(operation)) {
		OT_LOG_ERR("Out of memory");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}
}

void assign_key_ae(TEE_OperationHandle operation, TEE_ObjectHandle key)
{
	TEE_Attribute *sec_attr = NULL;

	sec_attr = get_attr_from_attrArr(TEE_ATTR_SECRET_VALUE,
					 key->key->gp_attrs.attrs,
					 key->key->gp_attrs.attrs_count);
	if (sec_attr == NULL) {
		OT_LOG(LOG_ERR, "TEE_ATTR_SECRET_VALUE not found");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	operation->ctx.gcm.key = sec_attr->content.ref.buffer;
}

TEE_Result TEE_AEInit(TEE_OperationHandle operation,
		      void *nonce, size_t nonceLen,
		      uint32_t tagLen,
		      uint32_t AADLen,
		      uint32_t payloadLen)
{
	TEE_Result rv_gp;
	int rv_mbedtls;
	int mode_mbedtls;

	AADLen = AADLen;
	payloadLen = payloadLen;
	
	if (operation == NULL) {
		OT_LOG_ERR("TEE_AEInit panics due operation NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.operationState != TEE_OPERATION_STATE_INITIAL) {
		OT_LOG_ERR("TEE_AEInit panics due operation state needs to be TEE_OPERATION_STATE_INITIAL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		OT_LOG_ERR("TEE_AEInit panics due operation key is not set");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.operationClass != TEE_OPERATION_AE) {
		OT_LOG_ERR("TEE_AEInit panics due operation class not TEE_OPERATION_AE");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED) {
		OT_LOG_ERR("TEE_AEInit panics due operation is initialized (call TEE_ResetOperation)");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}
	
	is_alg_supported(operation);

	rv_gp = valid_tag_len(tagLen);
	if (rv_gp != TEE_SUCCESS) {
		return rv_gp;
	}
	
	if (operation->operation_info.operationState == TEE_OPERATION_STATE_ACTIVE) {
		TEE_ResetOperation(operation);
	}
	
       	rv_mbedtls = mbedtls_gcm_setkey(operation->ctx.gcm.ctx,
					MBEDTLS_CIPHER_ID_AES,
					(const unsigned char *)operation->ctx.gcm.key,
					BYTES_TO_BITS(operation->key_data->key_lenght));
	if (rv_mbedtls) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG(LOG_ERR,"Error: Internal AE error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	mode_mbedtls = operation->operation_info.mode == TEE_MODE_ENCRYPT ? MBEDTLS_GCM_ENCRYPT : MBEDTLS_GCM_DECRYPT;

	rv_mbedtls = mbedtls_gcm_starts(operation->ctx.gcm.ctx, mode_mbedtls, nonce, nonceLen);
	if (rv_mbedtls) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG(LOG_ERR,"Error: Internal AE error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	operation->operation_info.digestLength = tagLen;
	operation->operation_info.handleState |= TEE_HANDLE_FLAG_INITIALIZED;
	operation->operation_info.operationState = TEE_OPERATION_STATE_ACTIVE;
	
	return TEE_SUCCESS;
}

void TEE_AEUpdateAAD(TEE_OperationHandle operation,
		     void *AADdata, size_t AADdataLen)
{
	int rv_mbedtls;
	
	if (operation == NULL) {
		OT_LOG_ERR("TEE_AEUpdateAAD panics due operation NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.operationState != TEE_OPERATION_STATE_ACTIVE) {
		OT_LOG_ERR("TEE_AEUpdateAAD panics due operation state needs to be TEE_OPERATION_STATE_ACTIVE");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		OT_LOG_ERR("TEE_AEUpdateAAD panics due operation key is not set");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.operationClass != TEE_OPERATION_AE) {
		OT_LOG_ERR("TEE_AEUpdateAAD panics due operation class not TEE_OPERATION_AE");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED)) {
		OT_LOG_ERR("TEE_AEUpdateAAD panics due operation is NOT initialized");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (AADdata == NULL) {
		OT_LOG_ERR("TEE_AEUpdateAAD panics due AADdata NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}
	
	is_alg_supported(operation);
	
	rv_mbedtls = mbedtls_gcm_update_ad(operation->ctx.gcm.ctx, AADdata, AADdataLen);
	if (rv_mbedtls) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG(LOG_ERR,"Error: Internal AE error");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}
}

TEE_Result TEE_AEUpdate(TEE_OperationHandle operation,
			void *srcData, size_t srcLen,
			void *destData, size_t *destLen)
{
	int rv_mbedtls;
	size_t mbedtls_output_len;

	if (operation == NULL) {
		OT_LOG_ERR("TEE_AEUpdate panics due operation NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.operationState != TEE_OPERATION_STATE_ACTIVE) {
		OT_LOG_ERR("TEE_AEUpdate panics due operation state "
			   "needs to be TEE_OPERATION_STATE_ACTIVE");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		OT_LOG_ERR("TEE_AEUpdate panics due operation key is not set");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.operationClass != TEE_OPERATION_AE) {
		OT_LOG_ERR("TEE_AEUpdate panics due operation class not TEE_OPERATION_AE");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED)) {
		OT_LOG_ERR("TEE_AEUpdate panics due operation is NOT initialized");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (srcData == NULL) {
		OT_LOG_ERR("TEE_AEUpdate panics due srcData NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (destData == NULL) {
		OT_LOG_ERR("TEE_AEUpdate panics due destData NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (destLen == NULL) {
		OT_LOG_ERR("TEE_AEUpdate panics due destLen NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (srcLen > *destLen) {
		OT_LOG_ERR("TEE_AEUpdate panics due destLen too short (srcLen[%lu]; "
			   "destLen[%lu])", srcLen, *destLen);
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}
	
	is_alg_supported(operation);
	
	rv_mbedtls = mbedtls_gcm_update(operation->ctx.gcm.ctx,
					srcData, srcLen,
					destData, *destLen,
					&mbedtls_output_len);
	if (rv_mbedtls) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG(LOG_ERR,"Error: Internal AE error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	*destLen = mbedtls_output_len;
	
	return TEE_SUCCESS;
}

TEE_Result TEE_AEEncryptFinal(TEE_OperationHandle operation,
			      void *srcData, size_t srcLen,
			      void *destData, size_t *destLen,
			      void *tag, size_t *tagLen)
{
	return do_ae_final(operation,
			   srcData, srcLen,
			   destData, destLen,
			   tag, tagLen);
}

TEE_Result TEE_AEDecryptFinal(TEE_OperationHandle operation,
			      void *srcData, size_t srcLen,
			      void *destData, size_t *destLen,
			      void *tag, size_t tagLen)
{
	return do_ae_final(operation,
			   srcData, srcLen,
			   destData, destLen,
			   tag, &tagLen);
}
