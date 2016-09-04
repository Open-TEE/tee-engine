#ifndef __CRYPTO_CIPHER_AE_H__
#define __CRYPTO_CIPHER_AE_H__

#include "tee_crypto_api.h"
#include "tee_shared_data_types.h"

TEE_Result init_gp_ae(TEE_OperationHandle operation);

void free_gp_ae(TEE_OperationHandle operation);

void reset_gp_ae(TEE_OperationHandle operation);

void assign_key_ae(TEE_OperationHandle operation, TEE_ObjectHandle key);

#endif /* __CRYPTO_CIPHER_AE_H__ */
