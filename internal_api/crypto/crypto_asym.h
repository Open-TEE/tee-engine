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

#ifndef __CRYPTO_ASYM_H__
#define __CRYPTO_ASYM_H__

#include <mbedtls/rsa.h>
#include <mbedtls/ecdsa.h>

#include "tee_crypto_api.h"
#include "tee_shared_data_types.h"
#include "storage/object_handle.h"

// mbedtls RSA key components sizes. NOTE: How we did get these values? It was done by generating
// RSA key with mbedtls and then calculated sizes from generated key.
#define mbedtls_RSA_LONGEST_COMPONENT(modulo)	(modulo)
#define mbedtls_RSA_PUBLIC_EXP_t		int
#define mbedtls_RSA_PUBLIC_EXP			sizeof(mbedtls_RSA_PUBLIC_EXP_t)
#define mbedtls_RSA_PRIVATE_EXP(modulo)		(modulo / 2)
#define mbedtls_RSA_PRIME_1(modulo)		(modulo / 2)
#define mbedtls_RSA_PRIME_2(modulo)		(modulo / 2)
#define mbedtls_RSA_EXPONENT_1(modulo)		(modulo / 2)
#define mbedtls_RSA_EXPONENT_2(modulo)		(modulo / 2)
#define mbedtls_RSA_COEFFICIENT(modulo)		(modulo / 2)

struct rsa_components {
	TEE_Attribute *modulo;
	TEE_Attribute *public_exp;
	TEE_Attribute *private_exp;
	TEE_Attribute *prime1;
	TEE_Attribute *prime2;
	TEE_Attribute *coff;
	TEE_Attribute *exp1;
	TEE_Attribute *exp2;
};

struct ecc_components {
	TEE_Attribute *x;
	TEE_Attribute *y;
	TEE_Attribute *private;
	TEE_Attribute *curve;
};

mbedtls_ecp_group_id gp_curve2mbedtls(obj_ecc_curve curve);

TEE_Result init_gp_asym(TEE_OperationHandle operation);

void free_gp_asym(TEE_OperationHandle operation);

bool assign_asym_key(TEE_OperationHandle op, TEE_ObjectHandle key);

bool assign_rsa_key_to_ctx(TEE_Attribute *attrs, uint32_t attrCount,
			   mbedtls_rsa_context *ctx,
			   uint32_t rsa_obj_type);

bool assign_ecc_key_to_ctx(TEE_Attribute *attrs, uint32_t attrCount,
			   mbedtls_ecdsa_context *ctx,
			   mbedtls_ecp_keypair *ec,
			   mbedtls_ecp_group *grp,
			   uint32_t ecc_obj_type);

void get_valid_rsa_components(TEE_Attribute *attrs, uint32_t attrCount,
			      struct rsa_components *rsa_comps);

void get_valid_ecc_components(TEE_Attribute *attrs, uint32_t attrCount,
			      struct ecc_components *ecc_comps);

#endif /* __CRYPTO_ASYM_H__ */
