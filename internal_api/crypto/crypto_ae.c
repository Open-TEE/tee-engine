#include <stddef.h>
#include <mbedtls/gcm.h>

#include "operation_handle.h"
#include "tee_logging.h"
#include "crypto_utils.h"

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
		OT_LOG_ERR("Not supported tagLen (provided[%u])", tagLen);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

static uint32_t is_alg_supported(TEE_OperationHandle operation)
{
	//OpenTEE internal sanity check
	if (operation->operation_info.algorithm != TEE_ALG_AES_GCM) {
		OT_LOG_ERR("Not supported algorithm (only TEE_ALG_AES_GCM)");
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}
}

TEE_Result init_gp_ae_cipher(TEE_OperationHandle operation)
{
	mbedtls_gcm_context *ae_ctx;
	int rv_mbedtls;
	TEE_Result res = TEE_ERROR_OUT_OF_MEMORY;

	ae_ctx = calloc(1, sizeof(mbedtls_gcm_context));
	if (ae_ctx == NULL) {
		OT_LOG_ERR("Out of memory");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	mbedtls_gcm_init(ae_ctx);

	operation->ctx = ae_ctx;

	return TEE_SUCCESS;
}

void free_gp_ae_cipher(TEE_OperationHandle operation)
{
	mbedtls_gcm_free(operation->ctx);
	free(operation->ctx);
}

void reset_gp_ae_cipher(TEE_OperationHandle operation)
{
	//Not sure about how to reset, because not reset function :/
	//TODO (NOTE): Breaks GP compatibility. Using malloc.

	free_gp_ae_cipher(operation);

	if (init_gp_ae_cipher(operation)) {
		OT_LOG_ERR("Out of memory");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}
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

	if (operation == NULL) {
		OT_LOG_ERR("TEE_AEInit panics due operation NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.algorithm != TEE_ALG_AES_GCM) {
		OT_LOG_ERR("TEE_AEInit panics due only supported algorithm is TEE_ALG_AES_GCM");
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	} else if (operation->operation_info.operationState != TEE_OPERATION_STATE_INITIAL) {
		OT_LOG_ERR("TEE_AEInit panics due operation state needs to be TEE_OPERATION_STATE_INITIAL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		OT_LOG_ERR("TEE_AEInit panics due operation key is not set");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.operationClass != TEE_OPERATION_AE) {
		OT_LOG_ERR("TEE_AEInit panics due operation class not TEE_OPERATION_AE");
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
	
       	rv_mbedtls = mbedtls_gcm_setkey(operation->ctx,
					MBEDTLS_CIPHER_ID_AES,
					(const unsigned char *)operation->key_data->key.secret.key,
					BYTES_TO_BITS(operation->key_data->key_lenght));
	if (rv_mbedtls) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG(LOG_ERR,"Error: Internal AE error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	mode_mbedtls = operation->operation_info.mode == TEE_MODE_ENCRYPT ? MBEDTLS_GCM_ENCRYPT : MBEDTLS_GCM_DECRYPT;

	rv_mbedtls = mbedtls_gcm_starts(operation->ctx, mode_mbedtls, nonce, nonceLen);
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
	if (operation == NULL) {
		OT_LOG_ERR("TEE_AEUpdateAAD panics due operation NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}
	
	is_alg_supported(operation);
	
	mbedtls_gcm_update_ad(operation->ctx, AADdata, AADdataLen);
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
	}
	
	is_alg_supported(operation);
	
	rv_mbedtls = mbedtls_gcm_update(operation->ctx,
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
	int rv_mbedtls;
	size_t mbedtls_output_len;
	char temp[100];
	size_t temp_s = 100;

	*tagLen = 16;
	rv_mbedtls = mbedtls_gcm_finish(operation->ctx,
					temp, temp_s,
					&mbedtls_output_len,
					tag, *tagLen);
	if (rv_mbedtls) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG(LOG_ERR,"Error: Internal AE error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	TEE_ResetOperation(operation);

	return TEE_SUCCESS;
}

TEE_Result TEE_AEDecryptFinal(TEE_OperationHandle operation,
			      void *srcData, size_t srcLen,
			      void *destData, size_t *destLen,
			      void *tag, size_t tagLen)
{
	operation = operation;
	srcData = srcData;
	srcLen = srcLen;
	destData = destData;
	destLen = destLen;
	tag = tag;
	tagLen = tagLen;

	return TEE_ERROR_NOT_SUPPORTED;
}
