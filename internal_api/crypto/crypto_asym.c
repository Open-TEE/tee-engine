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
	
#include <mbedtls/rsa.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>

#include "tee_internal_api.h"
#include "operation_handle.h"
#include "tee_crypto_api.h"
#include "tee_panic.h"
#include "tee_shared_data_types.h"
#include "tee_logging.h"
#include "storage/object_handle.h"
#include "storage/storage_utils.h"
#include "crypto_asym.h"
#include "crypto_utils.h"

//TODO: Maybe we should collect common functionality to function (RSA)

static mbedtls_md_type_t map_gp_pkcs_hash(uint32_t pkcs_algorithm)
{
	switch (pkcs_algorithm) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
		return MBEDTLS_MD_MD5;
		
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_ECDSA_SHA1:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
		return MBEDTLS_MD_SHA1;
		
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_ECDSA_SHA224:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
		return MBEDTLS_MD_SHA224;
		
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_ECDSA_SHA256:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
		return MBEDTLS_MD_SHA256;
		
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_ECDSA_SHA384:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
		return MBEDTLS_MD_SHA384;
		
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
	case TEE_ALG_ECDSA_SHA512:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
		return MBEDTLS_MD_SHA512;

	default:
		OT_LOG(LOG_ERR, "Internal: Not supported algorithm");
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	return MBEDTLS_MD_NONE;
}

static TEE_Result do_ecdsa_signature(TEE_OperationHandle operation,
				     void *digest, size_t digestLen,
				     void *signature, size_t *signatureLen)
{
	int rv_mbedtls;
	size_t sig_len;

	rv_mbedtls = mbedtls_ecdsa_write_signature(operation->ctx.ecc.ctx,
						   map_gp_pkcs_hash(operation->operation_info.algorithm),
						   digest, digestLen,
						   signature, *signatureLen,
						   &sig_len,
						   mbedtls_ctr_drbg_random,
						   &ot_mbedtls_ctr_drbg);
	
	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("Crypto problems: ECDSA Signature (search \"mbedtls\"-error from syslog)");

		if (MBEDTLS_ECDSA_MAX_LEN > *signatureLen)
			OT_LOG_ERR("Crypto problem: Safe signatureLen is [%u]", MBEDTLS_ECDSA_MAX_LEN);
		
		TEE_Panic(TEE_ERROR_GENERIC);
	}	
	
	*signatureLen = sig_len;
	return TEE_SUCCESS;
}

static TEE_Result do_ecdsa_verify(TEE_OperationHandle operation,
				     void *digest, size_t digestLen,
				     void *signature, size_t signatureLen)
{
	int rv_mbedtls;

	rv_mbedtls = mbedtls_ecdsa_read_signature(operation->ctx.ecc.ctx,
						  digest, digestLen,
						  signature, signatureLen);
	if (rv_mbedtls == MBEDTLS_ERR_ECP_BAD_INPUT_DATA) {
		return TEE_ERROR_SIGNATURE_INVALID;
	}

	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("Crypto problems: ECDSA verify (search \"mbedtls\"-error from syslog)");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	return TEE_SUCCESS;
}
static TEE_Result do_rsa_pkcs_signature(TEE_OperationHandle operation,
					void *digest, size_t digestLen,
					void *signature, size_t *signatureLen)
{
	size_t maxDigestLen;
	int rv_mbedtls;
	
	maxDigestLen = operation->key_data->key_lenght - 11;
	
	if (digestLen > maxDigestLen) {
		OT_LOG_ERR("Error (rsa signature): Digest lenght too big for RSA key "
			   "(digestLen[%lu]; maxDigestLenForKey[%lu])",
			   digestLen, maxDigestLen);
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (operation->key_data->key_lenght > *signatureLen) {
		OT_LOG_ERR("Error (rsa signature): Signature buffer short (provided[%lu]; required[%u])",
			   *signatureLen, operation->key_data->key_lenght);
		return TEE_ERROR_SHORT_BUFFER;
	}

	//OpenTEE internal sanity check. 
	rv_mbedtls = mbedtls_rsa_check_pubkey(operation->ctx.rsa.ctx);
	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("ERROR: internal crypto error (RSA signature; RSA key corrupted)");
		TEE_Panic(TEE_ERROR_GENERIC);
	}
	
	rv_mbedtls = mbedtls_rsa_rsassa_pkcs1_v15_sign(operation->ctx.rsa.ctx,
						       mbedtls_ctr_drbg_random,
						       &ot_mbedtls_ctr_drbg,
						       map_gp_pkcs_hash(operation->operation_info.algorithm),
						       get_alg_hash_lenght(operation->operation_info.algorithm),
						       digest,
						       signature);
		
	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("ERROR: Internal crypto error (RSA signature)");
		TEE_Panic(TEE_ERROR_GENERIC);
	}
	
	*signatureLen = operation->key_data->key_lenght;	
	return TEE_SUCCESS;
}

static TEE_Result do_rsa_pkcs_verify(TEE_OperationHandle operation,
				     void *digest, size_t digestLen,
				     void *signature, size_t signatureLen)
{
	size_t maxDigestLen;
	int rv_mbedtls;
	
	maxDigestLen = operation->key_data->key_lenght - 11;
	
	if (digestLen > maxDigestLen) {
		OT_LOG_ERR("Error (rsa verify): Digest lenght too big for RSA key "
			   "(digestLen[%lu]; maxDigestLenForKey[%lu])",
			   digestLen, maxDigestLen);
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}	
	
	if (operation->key_data->key_lenght != signatureLen) {
		OT_LOG_ERR("Error (rsa verify): Verify buffer short/big (provided[%lu]; required[%u])",
			   signatureLen, operation->key_data->key_lenght);
		return TEE_ERROR_SHORT_BUFFER;
	}

	//OpenTEE internal sanity check. 
	rv_mbedtls = mbedtls_rsa_check_privkey(operation->ctx.rsa.ctx);
	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("ERROR: internal crypto error (RSA verify; RSA key corrupted)");
		TEE_Panic(TEE_ERROR_GENERIC);
	}
	
	rv_mbedtls = mbedtls_rsa_rsassa_pkcs1_v15_verify(operation->ctx.rsa.ctx,
							 map_gp_pkcs_hash(operation->operation_info.algorithm),
							 digestLen,
							 digest,
							 signature);
	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("ERROR: Internal crypto error (RSA verify)");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	return TEE_SUCCESS;
}

static TEE_Result do_rsa_pkcs_encrypt(TEE_OperationHandle operation,
				      void *srcData, size_t srcLen,
				      void *destData, size_t *destLen)
{	
	size_t maxSrcLen;
	int rv_mbedtls;

	maxSrcLen = operation->key_data->key_lenght - 11;

	if (srcLen == 0) {
		OT_LOG_ERR("Error (rsa encrypt): srcLen is 0");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (srcLen > maxSrcLen) {
		OT_LOG_ERR("Error (rsa encrypt): srcLen too big (provided[%lu]; max[%lu])",
			   srcLen, maxSrcLen);
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (destLen == NULL) {
		OT_LOG_ERR("Error (rsa encrypt): destLen is NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->key_data->key_lenght > *destLen) {
		OT_LOG_ERR("Error (rsa encrypt): destLen too small (provided[%lu]; required[%u])",
			   *destLen, operation->key_data->key_lenght);
		return TEE_ERROR_SHORT_BUFFER;
	}

	if (operation->operation_info.algorithm == TEE_ALG_RSAES_PKCS1_V1_5) {
		rv_mbedtls = mbedtls_rsa_set_padding((mbedtls_rsa_context *)operation->ctx.rsa.ctx,
						     MBEDTLS_RSA_PKCS_V15, 0);
		if (rv_mbedtls) {
			print_mbedtls_to_syslog(rv_mbedtls);
			OT_LOG_ERR("ERROR: Internal error when setting RSA padding");
			TEE_Panic(TEE_ERROR_GENERIC);
		}

		rv_mbedtls = mbedtls_rsa_rsaes_pkcs1_v15_encrypt(operation->ctx.rsa.ctx,
								 mbedtls_ctr_drbg_random,
								 &ot_mbedtls_ctr_drbg,
								 srcLen, srcData, destData);
	} else {
		rv_mbedtls = mbedtls_rsa_set_padding((mbedtls_rsa_context *)operation->ctx.rsa.ctx,
						     MBEDTLS_RSA_PKCS_V21, map_gp_pkcs_hash(operation->operation_info.algorithm));
		if (rv_mbedtls) {
			print_mbedtls_to_syslog(rv_mbedtls);
			OT_LOG_ERR("ERROR: Internal error when setting RSA padding");
			TEE_Panic(TEE_ERROR_GENERIC);
		}

		rv_mbedtls = mbedtls_rsa_rsaes_oaep_encrypt(operation->ctx.rsa.ctx,
							    mbedtls_ctr_drbg_random,
							    &ot_mbedtls_ctr_drbg, NULL, 0,
							    srcLen, srcData, destData);
	}

	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("ERROR: Internal RSA encrypt error (1)");
		TEE_Panic(TEE_ERROR_GENERIC);
	} 

	*destLen = operation->key_data->key_lenght;
	
	return TEE_SUCCESS;
}

static TEE_Result do_rsa_pkcs_decrypt(TEE_OperationHandle operation,
				      void *srcData, size_t srcLen,
				      void *destData, size_t *destLen)
{
	size_t maxDstLen, mbedtlsOlen;
	int rv_mbedtls;

	maxDstLen = operation->key_data->key_lenght - 11;
	
	if (srcLen != operation->key_data->key_lenght) {
		OT_LOG_ERR("Error (rsa decrypt): srcLen too big/small (provided[%lu]; required[%u])",
			   srcLen, operation->key_data->key_lenght);
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (destLen == NULL) {
		OT_LOG_ERR("Error (rsa decrypt): destLen is NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (maxDstLen > *destLen) {
		OT_LOG_ERR("Error (rsa decrypt): destLen too small (provided[%lu]; required[%lu])",
			   *destLen, maxDstLen);
		return TEE_ERROR_SHORT_BUFFER;
	}
	
	if (operation->operation_info.algorithm == TEE_ALG_RSAES_PKCS1_V1_5) {
		rv_mbedtls = mbedtls_rsa_set_padding((mbedtls_rsa_context *)operation->ctx.rsa.ctx,
						     MBEDTLS_RSA_PKCS_V15, 0);
		if (rv_mbedtls) {
			print_mbedtls_to_syslog(rv_mbedtls);
			OT_LOG_ERR("ERROR: Internal error when setting RSA padding");
			TEE_Panic(TEE_ERROR_GENERIC);
		}

		mbedtlsOlen = *destLen;
		rv_mbedtls = mbedtls_rsa_rsaes_pkcs1_v15_decrypt(operation->ctx.rsa.ctx,
								 mbedtls_ctr_drbg_random,
								 &ot_mbedtls_ctr_drbg,
								 destLen, srcData, destData, mbedtlsOlen);
	} else {
		rv_mbedtls = mbedtls_rsa_set_padding((mbedtls_rsa_context *)operation->ctx.rsa.ctx,
						     MBEDTLS_RSA_PKCS_V21, map_gp_pkcs_hash(operation->operation_info.algorithm));

		if (rv_mbedtls) {
			print_mbedtls_to_syslog(rv_mbedtls);
			OT_LOG_ERR("ERROR: Internal error when setting RSA padding");
			TEE_Panic(TEE_ERROR_GENERIC);
		}

		mbedtlsOlen = *destLen;
		mbedtls_rsa_rsaes_oaep_decrypt(operation->ctx.rsa.ctx,
					       mbedtls_ctr_drbg_random,
					       &ot_mbedtls_ctr_drbg, NULL, 0,
					       destLen, srcData, destData, mbedtlsOlen);
	}

	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("ERROR: Internal RSA decrypt error (1)");
		TEE_Panic(TEE_ERROR_GENERIC);
	}
	
	return TEE_SUCCESS;
}

mbedtls_ecp_group_id gp_curve2mbedtls(obj_ecc_curve curve)
{
	switch (curve) {
	case TEE_ECC_CURVE_NIST_P192:
		return MBEDTLS_ECP_DP_SECP192R1;
	case TEE_ECC_CURVE_NIST_P224:
		return MBEDTLS_ECP_DP_SECP224R1;
	case TEE_ECC_CURVE_NIST_P256:
		return MBEDTLS_ECP_DP_SECP256R1;
	case TEE_ECC_CURVE_NIST_P384:
		return MBEDTLS_ECP_DP_SECP384R1;
	case TEE_ECC_CURVE_NIST_P521:
		return MBEDTLS_ECP_DP_SECP521R1;
	default:
		OT_LOG(LOG_ERR, "Curve is not supported");
		TEE_Panic(TEE_ERROR_GENERIC);
		return TEE_ERROR_GENERIC;
	}
}

void get_valid_ecc_components(TEE_Attribute *attrs, uint32_t attrCount,
			      struct ecc_components *ecc_comps)
{
	//For sanity sake everything is list 
	TEE_Attribute *x = 0, *y = 0, *private = 0, *curve = 0;
	
	if (attrs == NULL || ecc_comps == NULL) {
		OT_LOG(LOG_ERR, "NULLs are not support (key[%p]; rsa_comp[%p])", attrs, ecc_comps);
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	x = get_attr_from_attrArr(TEE_ATTR_ECC_PUBLIC_VALUE_X, attrs, attrCount);
	y = get_attr_from_attrArr(TEE_ATTR_ECC_PUBLIC_VALUE_Y, attrs, attrCount);
	private = get_attr_from_attrArr(TEE_ATTR_ECC_PRIVATE_VALUE, attrs, attrCount);
	curve = get_attr_from_attrArr(TEE_ATTR_ECC_CURVE, attrs, attrCount);

	//Following "dirty hack" is need for TEE_PopulateTransientObject
	//from persistant storage. Following requirement is NOT from
	//GP spec. Reference attribute is not valid: lenght is zero
	
	if (x && x->content.ref.length == 0)
		x = NULL;
	if (y && y->content.ref.length == 0)
		y = NULL;
	if (private && private->content.ref.length == 0)
		private = NULL;
	
	ecc_comps->x = x;
	ecc_comps->y = y;
	ecc_comps->private = private;
	ecc_comps->curve = curve;
}

void get_valid_rsa_components(TEE_Attribute *attrs, uint32_t attrCount,
			      struct rsa_components *rsa_comps)
{
	//For sanity sake everything is list 
	TEE_Attribute *modulo = 0, *public_exp = 0, *private_exp = 0, *prime1 = 0,
		*prime2 = 0, *coff = 0, *exp1 = 0, *exp2 = 0;
	
	if (attrs == NULL || rsa_comps == NULL) {
		OT_LOG(LOG_ERR, "NULLs are not support (key[%p]; rsa_comp[%p])", attrs, rsa_comps);
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	modulo = get_attr_from_attrArr(TEE_ATTR_RSA_MODULUS, attrs, attrCount);
	public_exp = get_attr_from_attrArr(TEE_ATTR_RSA_PUBLIC_EXPONENT, attrs, attrCount);
	private_exp = get_attr_from_attrArr(TEE_ATTR_RSA_PRIVATE_EXPONENT, attrs, attrCount);
	prime1 = get_attr_from_attrArr(TEE_ATTR_RSA_PRIME1, attrs, attrCount);
	prime2 = get_attr_from_attrArr(TEE_ATTR_RSA_PRIME2, attrs, attrCount);
	coff = get_attr_from_attrArr(TEE_ATTR_RSA_COEFFICIENT, attrs, attrCount);
	exp1 = get_attr_from_attrArr(TEE_ATTR_RSA_EXPONENT1, attrs, attrCount);
	exp2 = get_attr_from_attrArr(TEE_ATTR_RSA_EXPONENT2, attrs, attrCount);

	//Following "dirty hack" is need for TEE_PopulateTransientObject
	//from persistant storage. Following requirement is NOT from
	//GP spec. Reference attribute is not valid: lenght is zero
	
	if (modulo && modulo->content.ref.length == 0)
		modulo = NULL;
	if (public_exp && public_exp->content.ref.length == 0)
		public_exp = NULL;
	if (private_exp && private_exp->content.ref.length == 0)
		private_exp = NULL;
	if (prime1 && prime1->content.ref.length == 0)
		prime1 = NULL;
	if (prime2 && prime2->content.ref.length == 0)
		prime2 = NULL;
	if (coff && coff->content.ref.length == 0)
		coff = NULL;
	if (exp1 && exp1->content.ref.length == 0)
		exp1 = NULL;
	if (exp2 && exp2->content.ref.length == 0)
		exp2 = NULL;

	rsa_comps->modulo = modulo;
	rsa_comps->public_exp = public_exp;
	rsa_comps->private_exp = private_exp;
	rsa_comps->prime1 = prime1;
	rsa_comps->prime2 = prime2;
	rsa_comps->coff = coff;
	rsa_comps->exp1 = exp1;
	rsa_comps->exp2 = exp2;
}

bool assign_rsa_key_to_ctx(TEE_Attribute *attrs, uint32_t attrCount,
			   mbedtls_rsa_context *ctx,
			   uint32_t rsa_obj_type)
{
	struct rsa_components rsa_comps;
	int rv_mbedtls = 0;

	get_valid_rsa_components(attrs, attrCount, &rsa_comps);

	// NOTE: mbedtls_rsa_ctx need to be initialize! Call mbedtls_rsa_init()
	if (rsa_comps.modulo && rsa_comps.public_exp && !rsa_comps.private_exp && !rsa_comps.prime1 && !rsa_comps.prime2) {
		rv_mbedtls = mbedtls_rsa_import_raw(ctx,
						    rsa_comps.modulo->content.ref.buffer, rsa_comps.modulo->content.ref.length,
						    NULL, 0, //prime1
						    NULL, 0, //prime2
						    NULL, 0, //Private exp
						    rsa_comps.public_exp->content.ref.buffer, rsa_comps.public_exp->content.ref.length);
	} else if (rsa_comps.modulo && rsa_comps.public_exp && rsa_comps.private_exp && !rsa_comps.prime1 && !rsa_comps.prime2) {
		rv_mbedtls = mbedtls_rsa_import_raw(ctx,
						    rsa_comps.modulo->content.ref.buffer, rsa_comps.modulo->content.ref.length,
						    NULL, 0, //prime1
						    NULL, 0, //prime2
						    rsa_comps.private_exp->content.ref.buffer, rsa_comps.private_exp->content.ref.length,
						    rsa_comps.public_exp->content.ref.buffer, rsa_comps.public_exp->content.ref.length);
	} else if (rsa_comps.modulo && rsa_comps.public_exp && rsa_comps.private_exp && rsa_comps.prime1 && rsa_comps.prime2) {
		rv_mbedtls = mbedtls_rsa_import_raw(ctx,
						    rsa_comps.modulo->content.ref.buffer, rsa_comps.modulo->content.ref.length,
						    rsa_comps.prime1->content.ref.buffer, rsa_comps.prime1->content.ref.length,
						    rsa_comps.prime2->content.ref.buffer, rsa_comps.prime2->content.ref.length,
						    rsa_comps.private_exp->content.ref.buffer, rsa_comps.private_exp->content.ref.length,
						    rsa_comps.public_exp->content.ref.buffer, rsa_comps.public_exp->content.ref.length);
	} else {
		OT_LOG(LOG_ERR, "Not supported combination");
		TEE_Panic(TEE_ERROR_GENERIC);
		}

	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("ERROR: internal crypto error (RSA importing)");
		goto err;
	}

	rv_mbedtls = mbedtls_rsa_complete(ctx);
	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("ERROR: internal crypto error (RSA key population)");
		goto err;
	}
	
	rv_mbedtls = mbedtls_rsa_check_pubkey(ctx);
	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("ERROR: internal crypto error (RSA key population; public key)");
		goto err;
	}
	
	if (rsa_obj_type == TEE_TYPE_RSA_KEYPAIR) {
		rv_mbedtls = mbedtls_rsa_check_pubkey(ctx);
		if (rv_mbedtls != 0) {
			print_mbedtls_to_syslog(rv_mbedtls);
			OT_LOG_ERR("ERROR: internal crypto error (RSA key population; private key)");
			goto err;
		}
	}

	return true;
 err:
	return false;
}

bool assign_ecc_key_to_ctx(TEE_Attribute *attrs, uint32_t attrCount,
			   mbedtls_ecdsa_context *ctx,
			   mbedtls_ecp_keypair *ec,
			   mbedtls_ecp_group *grp,
			   uint32_t ecc_obj_type)
{
	struct ecc_components ecc_comps;
	int rv_mbedtls = 0;
	mbedtls_ecp_group_id select_curve;
	
	get_valid_ecc_components(attrs, attrCount, &ecc_comps);

	select_curve = gp_curve2mbedtls(ecc_comps.curve->content.value.a);
	
	rv_mbedtls = mbedtls_ecp_group_load(&ec->private_grp, select_curve);
	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("ERROR: internal crypto error (ECC importing; Curve)");
		goto err;
	}

	rv_mbedtls = mbedtls_ecp_group_load(grp, select_curve);
	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("ERROR: internal crypto error (ECC importing; Curve)");
		goto err;
	}
	
	rv_mbedtls = mbedtls_mpi_read_binary(&ec->private_Q.private_X, ecc_comps.x->content.ref.buffer, ecc_comps.x->content.ref.length);
	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("ERROR: internal crypto error (ECC importing; Qx)");
		goto err;
	}

	rv_mbedtls = mbedtls_mpi_read_binary(&ec->private_Q.private_Y, ecc_comps.y->content.ref.buffer, ecc_comps.y->content.ref.length);
	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("ERROR: internal crypto error (ECC importing; Qy)");
		goto err;
	}

	rv_mbedtls = mbedtls_mpi_lset(&ec->private_Q.private_Z, 1);
	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("ERROR: internal crypto error (ECC importing; Qz)");
		goto err;
	}
	
	if (ecc_obj_type == TEE_TYPE_ECDSA_KEYPAIR ||
	    ecc_obj_type == TEE_TYPE_ECDH_KEYPAIR) {
		
		rv_mbedtls = mbedtls_mpi_read_binary(&ec->private_d, ecc_comps.private->content.ref.buffer, ecc_comps.private->content.ref.length);
		if (rv_mbedtls != 0) {
			print_mbedtls_to_syslog(rv_mbedtls);
			OT_LOG_ERR("ERROR: internal crypto error (ECC importing; Private)");
			goto err;
		}
	}

	rv_mbedtls = mbedtls_ecp_check_pubkey(&ec->private_grp, &ec->private_Q);
	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("ERROR: internal crypto error (ECC importing: Public key failure)");
		goto err;
	}

	if (ecc_obj_type == TEE_TYPE_ECDSA_KEYPAIR ||
	    ecc_obj_type == TEE_TYPE_ECDH_KEYPAIR) {

		rv_mbedtls = mbedtls_ecp_check_privkey(&ec->private_grp, &ec->private_d);
		if (rv_mbedtls != 0) {
			print_mbedtls_to_syslog(rv_mbedtls);
			OT_LOG_ERR("ERROR: internal crypto error (ECC importing: Private key failure)");
			goto err;
		}
	}

	rv_mbedtls = mbedtls_ecdsa_from_keypair(ctx, ec);
	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("ERROR: internal crypto error key pairing(ECC importing: Pairing)");
		goto err;
	}
	
	return true;
 err:
	return false;
}



/*
 * crypto_asm.h functionality
 */
bool assign_asym_key(TEE_OperationHandle operation, TEE_ObjectHandle key)
{
	switch (operation->operation_info.algorithm) {
	case TEE_ALG_RSAES_PKCS1_V1_5:		
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
		return assign_rsa_key_to_ctx(key->key->gp_attrs.attrs,
					     key->key->gp_attrs.attrs_count,
					     operation->ctx.rsa.ctx,
					     key->objectInfo.objectType);
	case TEE_ALG_ECDSA_SHA1:
	case TEE_ALG_ECDSA_SHA224:
	case TEE_ALG_ECDSA_SHA256:
	case TEE_ALG_ECDSA_SHA384:
	case TEE_ALG_ECDSA_SHA512:
	case TEE_ALG_ECDH_DERIVE_SHARED_SECRET:
		return assign_ecc_key_to_ctx(key->key->gp_attrs.attrs,
					     key->key->gp_attrs.attrs_count,
					     operation->ctx.ecc.ctx,
					     operation->ctx.ecc.ec,
					     operation->ctx.ecc.grp,
					     key->objectInfo.objectType);
	default:
		OT_LOG_ERR("Not supported algorithm [%u]", operation->operation_info.algorithm);
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
		return false;
	}
}

TEE_Result init_gp_asym(TEE_OperationHandle operation)
{
	switch (operation->operation_info.algorithm) {
	case TEE_ALG_RSAES_PKCS1_V1_5:		
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
		operation->ctx.rsa.ctx = calloc(1, sizeof(mbedtls_rsa_context));
		if (operation->ctx.rsa.ctx == NULL) {
			OT_LOG(LOG_ERR, "Out of memory");
			return TEE_ERROR_OUT_OF_MEMORY;
		}

		mbedtls_rsa_init(operation->ctx.rsa.ctx);
	
		break;
	case TEE_ALG_ECDSA_SHA1:
	case TEE_ALG_ECDSA_SHA224:
	case TEE_ALG_ECDSA_SHA256:
	case TEE_ALG_ECDSA_SHA384:
	case TEE_ALG_ECDSA_SHA512:
	case TEE_ALG_ECDH_DERIVE_SHARED_SECRET:	
		operation->ctx.ecc.ctx = calloc(1, sizeof(mbedtls_ecdsa_context));
		operation->ctx.ecc.ec = calloc(1, sizeof(mbedtls_ecp_keypair));
		operation->ctx.ecc.grp = calloc(1, sizeof(mbedtls_ecp_group));
		if (operation->ctx.ecc.ctx == NULL ||
		    operation->ctx.ecc.ec == NULL ||
		    operation->ctx.ecc.grp == NULL) {
			OT_LOG(LOG_ERR, "Out of memory");
			return TEE_ERROR_OUT_OF_MEMORY;
		}

		mbedtls_ecdsa_init(operation->ctx.ecc.ctx);
		mbedtls_ecp_keypair_init(operation->ctx.ecc.ec);
		mbedtls_ecp_group_init(operation->ctx.ecc.grp);
		break;
		
	default:
		OT_LOG_ERR("Not supported algorithm [%u]", operation->operation_info.algorithm);
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	//Leave as a documentation purpose. Single state operation are never initialized
	//operation->operation_info.handleState |= TEE_HANDLE_FLAG_INITIALIZED;
	
	return TEE_SUCCESS;
}

void free_gp_asym(TEE_OperationHandle operation)
{
		switch (operation->operation_info.algorithm) {
	case TEE_ALG_RSAES_PKCS1_V1_5:		
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
		mbedtls_rsa_free(operation->ctx.rsa.ctx);
		free(operation->ctx.rsa.ctx);
		operation->ctx.rsa.ctx = NULL;
		break;
		
	case TEE_ALG_ECDSA_SHA1:
	case TEE_ALG_ECDSA_SHA224:
	case TEE_ALG_ECDSA_SHA256:
	case TEE_ALG_ECDSA_SHA384:
	case TEE_ALG_ECDSA_SHA512:
	case TEE_ALG_ECDH_DERIVE_SHARED_SECRET:	
		mbedtls_ecdsa_free(operation->ctx.ecc.ctx);
		mbedtls_ecp_keypair_free(operation->ctx.ecc.ec);
		mbedtls_ecp_group_free(operation->ctx.ecc.grp);
		free(operation->ctx.ecc.ctx);
		free(operation->ctx.ecc.ec);
		free(operation->ctx.ecc.grp);
		operation->ctx.ecc.ctx = NULL;
		operation->ctx.ecc.ec = NULL;
		operation->ctx.ecc.grp = NULL;
		break;
		
	default:
		OT_LOG_ERR("Not supported algorithm [%u]", operation->operation_info.algorithm);
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}
}

/*
 * GP TEE Core API functions
 */

TEE_Result TEE_AsymmetricEncrypt(TEE_OperationHandle operation,
				 TEE_Attribute *params, uint32_t paramCount,
				 void *srcData, size_t srcLen,
				 void *destData, size_t *destLen)
{
	params = params;
	paramCount = paramCount;
	
	if (operation == NULL) {
		OT_LOG_ERR("TEE_AsymmetricEncrypt panics due operation NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (srcData == NULL) {
		OT_LOG_ERR("TEE_AsymmetricEncrypt panics due srcData NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (destData == NULL) {
		OT_LOG_ERR("TEE_AsymmetricEncrypt panics due destData NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);		
	} else if (destLen == NULL) {
		OT_LOG_ERR("TEE_AsymmetricEncrypt panics due destLen NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.mode != TEE_MODE_ENCRYPT) {
		OT_LOG_ERR("TEE_AsymmetricEncrypt panics due operation mode NOT TEE_MODE_ENCRYPT");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.operationClass != TEE_OPERATION_ASYMMETRIC_CIPHER) {
		OT_LOG_ERR("TEE_AsymmetricEncrypt panics due operation "
			   "class NOT TEE_OPERATION_ASYMMETRIC_CIPHER");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		OT_LOG_ERR("TEE_AsymmetricEncrypt panics due operation key is not set");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	switch (operation->operation_info.algorithm) {
	case TEE_ALG_RSAES_PKCS1_V1_5:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
		return do_rsa_pkcs_encrypt(operation, srcData, srcLen, destData, destLen);
	default:
		OT_LOG_ERR("TEE_AsymmetricEncrypt panics due not supported "
			   "algorithm [%u]", operation->operation_info.algorithm);
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	OT_LOG_ERR("TEE_AsymmetricEncrypt something wrong (internal)");
	return TEE_ERROR_GENERIC;// Never end up here
}

TEE_Result TEE_AsymmetricDecrypt(TEE_OperationHandle operation,
				 TEE_Attribute *params, uint32_t paramCount,
				 void *srcData, size_t srcLen,
				 void *destData, size_t *destLen)
{
	params = params;
	paramCount = paramCount;

	if (operation == NULL) {
		OT_LOG_ERR("TEE_AsymmetricDecrypt panics due operation NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (srcData == NULL) {
		OT_LOG_ERR("TEE_AsymmetricDecrypt panics due srcData NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);	
	} else if (destData == NULL) {
		OT_LOG_ERR("TEE_AsymmetricDecrypt panics due destData NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);		
	} else if (destLen == NULL) {
		OT_LOG_ERR("TEE_AsymmetricDecrypt panics due destLen NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.mode != TEE_MODE_DECRYPT) {
		OT_LOG_ERR("TEE_AsymmetricDecrypt panics due operation mode not TEE_MODE_DECRYPT");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.operationClass != TEE_OPERATION_ASYMMETRIC_CIPHER) {
		OT_LOG_ERR("TEE_AsymmetricDecrypt panics due operation class not TEE_OPERATION_ASYMMETRIC_CIPHER");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		OT_LOG_ERR("TEE_AsymmetricDecrypt panics due operation key is not set");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	switch (operation->operation_info.algorithm) {
	case TEE_ALG_RSAES_PKCS1_V1_5:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
		return do_rsa_pkcs_decrypt(operation, srcData, srcLen, destData, destLen);
	default:
		OT_LOG_ERR("TEE_AsymmetricDecrypt panics due algorithm not supported [%u]",
			   operation->operation_info.algorithm);
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	return TEE_ERROR_GENERIC; /* Never end up here */
}

TEE_Result TEE_AsymmetricSignDigest(TEE_OperationHandle operation,
				    TEE_Attribute *params, uint32_t paramCount,
				    void *digest, size_t digestLen,
				    void *signature, size_t *signatureLen)
{
	params = params;
	paramCount = paramCount;

	if (operation == NULL) {
		OT_LOG_ERR("TEE_AsymmetricSignDigest panics due operation NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (signatureLen == NULL) {
		OT_LOG_ERR("TEE_AsymmetricSignDigest panics due signatureLen NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (signature == NULL) {
		OT_LOG_ERR("TEE_AsymmetricSignDigest panics due signature NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (digest == NULL) {
		OT_LOG_ERR("TEE_AsymmetricSignDigest panics due digest NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.mode != TEE_MODE_SIGN) {
		OT_LOG_ERR("TEE_AsymmetricSignDigest panics due operation mode is not TEE_MODE_SIGN");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.operationClass != TEE_OPERATION_ASYMMETRIC_SIGNATURE) {
		OT_LOG_ERR("TEE_AsymmetricSignDigest panics due "
			   "operation class is not TEE_OPERATION_ASYMMETRIC_SIGNATURE");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		OT_LOG_ERR("TEE_AsymmetricSignDigest panics due operation key is NOT set");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} 

	if (digestLen != get_alg_hash_lenght(operation->operation_info.algorithm)) {
		OT_LOG_ERR("TEE_AsymmetricSignDigest panics due digestLen mismatch "
			   "(expected[%lu]; provided[%lu])",
			   get_alg_hash_lenght(operation->operation_info.algorithm),
			   digestLen);
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	switch (operation->operation_info.algorithm) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		return do_rsa_pkcs_signature(operation, digest, digestLen, signature, signatureLen);
	case TEE_ALG_ECDSA_SHA1:
	case TEE_ALG_ECDSA_SHA224:
	case TEE_ALG_ECDSA_SHA256:
	case TEE_ALG_ECDSA_SHA384:
	case TEE_ALG_ECDSA_SHA512:
		return do_ecdsa_signature(operation, digest, digestLen, signature, signatureLen);
	default:
		OT_LOG_ERR("TEE_AsymmetricSignDigest panics due algorithm not supported "
			   "(algorithm[%u])",operation->operation_info.algorithm);
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	return TEE_ERROR_GENERIC; /* Never end up here */
}

TEE_Result TEE_AsymmetricVerifyDigest(TEE_OperationHandle operation,
				      TEE_Attribute *params, uint32_t paramCount,
				      void *digest, size_t digestLen,
				      void *signature, size_t signatureLen)
{
	params = params;
	paramCount = paramCount;
	
	if (operation == NULL) {
		OT_LOG_ERR("TEE_AsymmetricVerifyDigest panics due operation NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (digest == NULL) {
		OT_LOG_ERR("TEE_AsymmetricVerifyDigest panics due digest NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (signature == NULL) {
		OT_LOG_ERR("TEE_AsymmetricVerifyDigest panics due signature NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.mode != TEE_MODE_VERIFY) {
		OT_LOG_ERR("TEE_AsymmetricVerifyDigest panics due operation mode not TEE_MODE_VERIFY");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.operationClass != TEE_OPERATION_ASYMMETRIC_SIGNATURE) {
		OT_LOG_ERR("TEE_AsymmetricVerifyDigest panics due operation "
			   "class not TEE_OPERATION_ASYMMETRIC_SIGNATURE");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		OT_LOG_ERR("TEE_AsymmetricVerifyDigest panics due operation key is not set");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}
	
	if (digestLen != get_alg_hash_lenght(operation->operation_info.algorithm)) {
		OT_LOG_ERR("TEE_AsymmetricVerifyDigest panics due digestLen mismatch "
			   "(expected[%lu]; provided[%lu])",
			   get_alg_hash_lenght(operation->operation_info.algorithm),
			   digestLen);
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	switch (operation->operation_info.algorithm) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		return do_rsa_pkcs_verify(operation, digest, digestLen, signature, signatureLen);
	case TEE_ALG_ECDSA_SHA1:
	case TEE_ALG_ECDSA_SHA224:
	case TEE_ALG_ECDSA_SHA256:
	case TEE_ALG_ECDSA_SHA384:
	case TEE_ALG_ECDSA_SHA512:
		return do_ecdsa_verify(operation, digest, digestLen, signature, signatureLen);
	default:
		OT_LOG_ERR("TEE_AsymmetricVerifyDigest panics due algorithm not supported "
			   "(algorithm[%u])",operation->operation_info.algorithm);
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	return TEE_ERROR_GENERIC; /* Never end up here */
}
