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

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>

#include <stdlib.h>
#include <string.h>

#include "object_handle.h"
#include "storage_utils.h"
#include "tee_logging.h"
#include "tee_storage_api.h"
#include "tee_panic.h"
#include "crypto/operation_handle.h"
#include "crypto/crypto_asym.h"
#include "tee_internal_api.h"
#include "crypto/crypto_utils.h"

static int malloc_attr(TEE_Attribute *init_attr,
		       uint32_t attrID,
		       uint32_t buf_len)
{
	init_attr->attributeID = attrID;
	
	if (buf_len == 0) {
		return 0;
	}
	
	init_attr->content.ref.buffer = calloc(1, buf_len);
	if (init_attr->content.ref.buffer == NULL) {
		OT_LOG_ERR("Malloc failed");
		return 1;
	}
	
	init_attr->content.ref.length = 0; //Nothing initilaized
	return 0;
}

static TEE_Attribute *copy_attr2gpKeyAttr(struct gp_key *key,
					  TEE_Attribute *cpy_attr)
{
	TEE_Attribute *gp_attr;

	if (cpy_attr == NULL) {
		return NULL;
	}
	
	gp_attr = get_attr_from_attrArr(cpy_attr->attributeID,
					key->gp_attrs.attrs, key->gp_attrs.attrs_count);
	
	if (gp_attr == NULL) {
		OT_LOG(LOG_ERR, "No GP key attribute to copy"
		       "attribute (cpy_attr[%u])", cpy_attr->attributeID);
		TEE_Panic(TEE_ERROR_GENERIC); /* Should never happen */
	}

	if (is_value_attribute(gp_attr->attributeID)) {
		memcpy(gp_attr, cpy_attr, sizeof(TEE_Attribute));
		return gp_attr;
	}

	if (cpy_attr->content.ref.length > key->key_max_length) {
		OT_LOG_ERR("GP key too small for attribute (attributeID[%u]; "
			   "provideLen[%lu]; maxLen[%lu])",
			   cpy_attr->attributeID,
			   cpy_attr->content.ref.length,
			   gp_attr->content.ref.length);
		TEE_Panic(TEE_ERROR_GENERIC); /* Should never happen */
	}

	gp_attr->content.ref.length = cpy_attr->content.ref.length;
	TEE_MemMove(gp_attr->content.ref.buffer,
		    cpy_attr->content.ref.buffer,
		    cpy_attr->content.ref.length);

	return gp_attr;
}

static void copy_attr2mbedtlsMpi(mbedtls_mpi *mpi,
				 TEE_Attribute *gp_attr,
				 uint32_t maxRefSize)
{
	size_t mpi_len;
	
	if (gp_attr == NULL || mpi == NULL) {
		OT_LOG(LOG_ERR, "Panicking due mpi or gp_attr null");
		TEE_Panic(TEE_ERROR_GENERIC); /* Should never happen */
	}

	mpi_len = mbedtls_mpi_size(mpi);

	if (mpi_len > maxRefSize) {
		OT_LOG(LOG_ERR, "Internal error: mpi too big for reference (mpi[%lu]; "
		       "refMaxLen[%u]; attrID[%u])", mpi_len, maxRefSize, gp_attr->attributeID);
		TEE_Panic(TEE_ERROR_GENERIC);//Should never happen
	}

	gp_attr->content.ref.length = mpi_len;
	if (mbedtls_mpi_write_binary(mpi, gp_attr->content.ref.buffer, gp_attr->content.ref.length)) {
		OT_LOG(LOG_ERR, "Panicking due mbedtls_mpi_read_binary failed");
		TEE_Panic(TEE_ERROR_GENERIC);
	}
}

/* Secret key attribute is used for AES, DES, DES3 and HMAC operations */
static TEE_Result populate_secret_key(TEE_Attribute *attrs,
				      uint32_t attrCount,
				      struct gp_key *key)
{
	TEE_Attribute *secret_attr;

	secret_attr = get_attr_from_attrArr(TEE_ATTR_SECRET_VALUE, attrs, attrCount);
	if (secret_attr == NULL) {
		OT_LOG_ERR("Unable find TEE_ATTR_SECRET_VALUE attribute");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (secret_attr->content.ref.length > key->key_max_length) {
		OT_LOG_ERR("Key too big: reserved size [%u]; populated size [%lu]",
			   key->key_max_length, secret_attr->content.ref.length);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	copy_attr2gpKeyAttr(key, secret_attr);
	key->key_lenght = secret_attr->content.ref.length;

	return TEE_SUCCESS;
}

static TEE_Result populate_rsa_key(TEE_Attribute *attrs,
				   uint32_t attrCount,
				   struct gp_key *key,
				   uint32_t rsa_obj_type)
{
	//TODO: Add private key and parameters checks
	struct rsa_components rsa_comp;
	mbedtls_rsa_context rsa_ctx;
	uint32_t rsa_max_comp_size;
	TEE_Result rv_gp = TEE_ERROR_GENERIC;
	
	mbedtls_rsa_init(&rsa_ctx);
	
	get_valid_rsa_components(attrs, attrCount, &rsa_comp);

	//Check components

	if (rsa_comp.modulo == NULL || rsa_comp.public_exp == NULL) {
		OT_LOG_ERR("Panicking due missing RSA key TEE_ATTR_RSA_MODULUS or "
			   "TEE_ATTR_RSA_PUBLIC_EXPONENT");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (rsa_comp.modulo->content.ref.length > key->key_max_length) {
		OT_LOG_ERR("Panicking due RSA key too big: reserved size [%u]; "
			   "provided size [%lu]",key->key_max_length,
			   rsa_comp.modulo->content.ref.length);
		rv_gp = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

	if (rsa_comp.public_exp->content.ref.length > mbedtls_RSA_PUBLIC_EXP) {
		OT_LOG_ERR("Panics due TEE_ATTR_RSA_PUBLIC_EXPONENT too big. "
			   "OpenTEE limits public exponent to 4 bytes!");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}
	
	rsa_max_comp_size = mbedtls_RSA_LONGEST_COMPONENT(key->key_max_length);
	
	if (key->gp_key_type == TEE_TYPE_RSA_KEYPAIR) {

		if (rsa_comp.private_exp == NULL) {
			OT_LOG_ERR("Panicking due missing RSA key TEE_ATTR_RSA_PRIVATE_EXPONENT");
			TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
		}

		if (rsa_comp.private_exp->content.ref.length > rsa_max_comp_size) {
			OT_LOG_ERR("Panicking due private exponent size mismatch: "
				   "reserved size [%lu]; provided size [%lu]",
				   rsa_comp.private_exp->content.ref.length,
				   mbedtls_RSA_PRIVATE_EXP(rsa_comp.modulo->content.ref.length));
			rv_gp = TEE_ERROR_BAD_PARAMETERS;
			goto err;
		}
		
		if (rsa_comp.prime1 || rsa_comp.prime2 ||
		    rsa_comp.coff ||
		    rsa_comp.exp1 || rsa_comp.exp2) {
			
			if (rsa_comp.prime1 == NULL  || rsa_comp.prime2 == NULL  ||
			    rsa_comp.coff == NULL  ||
			    rsa_comp.exp1 == NULL  || rsa_comp.exp2 == NULL) {
				OT_LOG_ERR("Panicking due missing RSA component "
					   "(need to provide all or none)");
				TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
			}

			if (rsa_comp.prime1->content.ref.length > rsa_max_comp_size ||
			    rsa_comp.prime2->content.ref.length > rsa_max_comp_size ||
			    rsa_comp.exp1->content.ref.length > rsa_max_comp_size ||
			    rsa_comp.exp2->content.ref.length > rsa_max_comp_size ||
			    rsa_comp.coff->content.ref.length > rsa_max_comp_size) {
				OT_LOG(LOG_ERR, "Panics due RSA some of the RSA components is too "
				       "big (prime1/2 or exp1/2 or coff)");
				TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
			}

			OT_LOG_ERR("NOTE: Unfotunately OpenTEE is not able to use "
				   "Exponent1, Exponent2 and Cofficient. They are regenerated "
				   "from other parameters!!");
		}
	}

	// -- Parameters are OK --

	//Test key

	if (!assign_rsa_key_to_ctx(attrs, attrCount, &rsa_ctx, rsa_obj_type)) {
		OT_LOG_ERR("Key is not usable in OpenTEE");
		rv_gp = TEE_ERROR_GENERIC;
		goto err;
	}

	//Key is OK. Copy attributes to key.
	copy_attr2gpKeyAttr(key, rsa_comp.modulo);
	copy_attr2gpKeyAttr(key, rsa_comp.public_exp);
	copy_attr2gpKeyAttr(key, rsa_comp.prime1);
	copy_attr2gpKeyAttr(key, rsa_comp.prime2);
	copy_attr2gpKeyAttr(key, rsa_comp.exp1);
	copy_attr2gpKeyAttr(key, rsa_comp.exp2);
	copy_attr2gpKeyAttr(key, rsa_comp.coff);
	copy_attr2gpKeyAttr(key, rsa_comp.private_exp);
	
	key->key_lenght = rsa_comp.modulo->content.ref.length;
	rv_gp = TEE_SUCCESS;
 err:
	mbedtls_rsa_free(&rsa_ctx);
	return rv_gp;
}

static TEE_Result populate_ecc_key(TEE_Attribute *attrs,
				   uint32_t attrCount,
				   struct gp_key *key,
				   uint32_t ecc_obj_type)
{
	//TODO: Add private key and parameters checks
	struct ecc_components ecc_comp;
	mbedtls_ecdsa_context ecc_ctx;
	mbedtls_ecp_keypair ec;
	mbedtls_ecp_group grp;
	TEE_Result rv_gp = TEE_ERROR_GENERIC;

	//mbedtls_ecdsa_init(&ecc_ctx);

	mbedtls_ecp_group_init(&grp);
	mbedtls_ecdsa_init(&ecc_ctx);
	mbedtls_ecp_keypair_init(&ec);

	get_valid_ecc_components(attrs, attrCount, &ecc_comp);

	//Check components

	if (ecc_comp.x == NULL || ecc_comp.y == NULL || ecc_comp.curve == NULL) {
		OT_LOG_ERR("Panicking due missing ECC component: "
			   "TEE_ATTR_ECC_PUBLIC_VALUE_X [%p]; "
			   "TEE_ATTR_ECC_PUBLIC_VALUE_Y [%p]; "
			   "TEE_ATTR_ECC_CURVE [%p]",
			   ecc_comp.x, ecc_comp.y, ecc_comp.curve);
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (valid_ecc_curve(ecc_comp.curve)) {
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	//TODO Check lenghts
	
	if (key->gp_key_type == TEE_TYPE_ECDSA_KEYPAIR ||
	    key->gp_key_type == TEE_TYPE_ECDH_KEYPAIR) {

		if (ecc_comp.private == NULL) {
			OT_LOG_ERR("Panicking due missing ECC TEE_ATTR_ECC_PRIVATE_VALUE");
			TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
		}

		/*
		if (ecc_comp.private_exp->content.ref.length > rsa_max_comp_size) {
			OT_LOG_ERR("Panicking due private exponent size mismatch: "
				   "reserved size [%lu]; provided size [%lu]",
				   rsa_comp.private_exp->content.ref.length,
				   mbedtls_RSA_PRIVATE_EXP(rsa_comp.modulo->content.ref.length));
			rv_gp = TEE_ERROR_BAD_PARAMETERS;
			goto err;
			}*/
	}

	// -- Parameters are OK --

	//Test key
	if (!assign_ecc_key_to_ctx(attrs, attrCount, &ecc_ctx, &ec, &grp, ecc_obj_type)) {
		OT_LOG_ERR("Key is not usable in OpenTEE");
		rv_gp = TEE_ERROR_GENERIC;
		goto err;
	}

	//Key is OK. Copy attributes to key.
	copy_attr2gpKeyAttr(key, ecc_comp.x);
	copy_attr2gpKeyAttr(key, ecc_comp.y);
	copy_attr2gpKeyAttr(key, ecc_comp.curve);
	copy_attr2gpKeyAttr(key, ecc_comp.private);
	
	key->key_lenght = ecc_comp.x->content.ref.length;
	rv_gp = TEE_SUCCESS;
 err:
	mbedtls_ecdsa_free(&ecc_ctx);
	mbedtls_ecp_keypair_free(&ec);
	mbedtls_ecp_group_free(&grp);
	return rv_gp;
}

static int malloc_rsa_attrs(struct gp_key *key,
			    uint32_t objectType,
			    uint32_t maxObjectSize)
{
	uint32_t rsa_comp_size;
	int index = 0;

	//TODO(improvement): Memory optimization. Reserve only need size. 

	rsa_comp_size = mbedtls_RSA_LONGEST_COMPONENT(maxObjectSize);
	
	/* Modulo: Modulo is key size */
	/* Public exponent: e points to memory of 4 bytes in size (mbedtls RSA) */
	if (malloc_attr(&key->gp_attrs.attrs[index++], TEE_ATTR_RSA_MODULUS, rsa_comp_size) ||
	    malloc_attr(&key->gp_attrs.attrs[index++], TEE_ATTR_RSA_PUBLIC_EXPONENT, rsa_comp_size)) {
		goto err;
	}

	if (objectType == TEE_TYPE_RSA_PUBLIC_KEY) {
		return 0;
	}

	if (malloc_attr(&key->gp_attrs.attrs[index++], TEE_ATTR_RSA_PRIVATE_EXPONENT, rsa_comp_size) ||
	    malloc_attr(&key->gp_attrs.attrs[index++], TEE_ATTR_RSA_PRIME1, rsa_comp_size) ||
	    malloc_attr(&key->gp_attrs.attrs[index++], TEE_ATTR_RSA_PRIME2, rsa_comp_size) ||
	    malloc_attr(&key->gp_attrs.attrs[index++], TEE_ATTR_RSA_EXPONENT1, rsa_comp_size) ||
	    malloc_attr(&key->gp_attrs.attrs[index++], TEE_ATTR_RSA_EXPONENT2, rsa_comp_size) ||
	    malloc_attr(&key->gp_attrs.attrs[index++], TEE_ATTR_RSA_COEFFICIENT, rsa_comp_size)) {
		goto err;
	}

	return 0;

err:
	free_gp_attributes(&key->gp_attrs);
	return 1;
}

static int malloc_ecc_attrs(struct gp_key *key,
			      uint32_t objectType,
			      uint32_t maxObjectSize)
{
	int index = 0;

	//TODO(improvement): Memory optimization. Reserve only need size. 

	if (malloc_attr(&key->gp_attrs.attrs[index++], TEE_ATTR_ECC_PUBLIC_VALUE_X, maxObjectSize) ||
	    malloc_attr(&key->gp_attrs.attrs[index++], TEE_ATTR_ECC_CURVE, 0) ||
	    malloc_attr(&key->gp_attrs.attrs[index++], TEE_ATTR_ECC_PUBLIC_VALUE_Y, maxObjectSize)) {
		goto err;
	}

	if (objectType == TEE_TYPE_ECDSA_PUBLIC_KEY ||
	    objectType == TEE_TYPE_ECDH_PUBLIC_KEY) {
		return 0;
	}

	if (malloc_attr(&key->gp_attrs.attrs[index++], TEE_ATTR_ECC_PRIVATE_VALUE, maxObjectSize)) {
		goto err;
	}

	return 0;

err:
	free_gp_attributes(&key->gp_attrs);
	return 1;
}

static int malloc_gp_key_struct(struct gp_key **key,
				uint32_t objectType,
				uint32_t maxObjectSize)
{
	*key = (struct gp_key *)calloc(1, sizeof(struct gp_key));
	if (*key == NULL) {
		OT_LOG_ERR("Malloc failed\n");
		goto err_1;
	}

	if (expected_object_attr_count(objectType, &(*key)->gp_attrs.attrs_count)) {
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	(*key)->gp_attrs.attrs =
		(TEE_Attribute *)calloc(1, sizeof(TEE_Attribute) * (*key)->gp_attrs.attrs_count);
	if ((*key)->gp_attrs.attrs == NULL) {
		OT_LOG_ERR("Malloc failed");
		goto err_2;
	}

	switch (objectType) {
	case TEE_TYPE_AES:
	case TEE_TYPE_HMAC_MD5:
	case TEE_TYPE_HMAC_SHA1:
	case TEE_TYPE_HMAC_SHA224:
	case TEE_TYPE_HMAC_SHA256:
	case TEE_TYPE_HMAC_SHA384:
	case TEE_TYPE_HMAC_SHA512:
	case TEE_TYPE_GENERIC_SECRET:
		if (malloc_attr((*key)->gp_attrs.attrs, TEE_ATTR_SECRET_VALUE, maxObjectSize)) {
			goto err_2;
		}

		break;

	case TEE_TYPE_RSA_PUBLIC_KEY:
	case TEE_TYPE_RSA_KEYPAIR:
		if (malloc_rsa_attrs(*key, objectType, maxObjectSize)) {
			goto err_2;
		}
		break;

	case TEE_TYPE_ECDH_KEYPAIR:
	case TEE_TYPE_ECDH_PUBLIC_KEY:
	case TEE_TYPE_ECDSA_PUBLIC_KEY:
	case TEE_TYPE_ECDSA_KEYPAIR:
		if (malloc_ecc_attrs(*key, objectType, maxObjectSize)) {
			goto err_2;
		}
		break;
	default:
		OT_LOG(LOG_ERR, "Not supported objecttype [%u]", objectType);
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	(*key)->gp_key_type = objectType;
	(*key)->key_max_length = maxObjectSize;

	return 0;

err_2:
	free(*key);
err_1:
	*key = 0;
	return 1;
}

static TEE_Result gen_symmetric_key(struct gp_key *key,
				    uint32_t keySize)
{
	TEE_Attribute *sec_attr = NULL;
	
	sec_attr = get_attr_from_attrArr(TEE_ATTR_SECRET_VALUE, key->gp_attrs.attrs, key->gp_attrs.attrs_count);
	if (sec_attr == NULL) {
		OT_LOG(LOG_ERR, "TEE_ATTR_SECRET_VALUE not found");
		TEE_Panic(TEE_ERROR_GENERIC);
	}
	
	TEE_GenerateRandom(sec_attr->content.ref.buffer, keySize);
	sec_attr->content.ref.length = keySize;
	return TEE_SUCCESS;
}

static TEE_Result gen_rsa_keypair(struct gp_key *key,
				  uint32_t keySize,
				  TEE_Attribute *params,
				  uint32_t paramCount)
{
	//Initialized with default value,
	//if user does not provide public exponent
	//mbedtls_RSA_PUBLIC_EXP_t pub_exp = 65537;
	int pub_exp = 65537;
	TEE_Attribute *usr_rsa_public_exp = NULL;
	int rv_mbedtls = 0;
	unsigned int keySize_u_int = BYTE2BITS(keySize);
	TEE_Result rv_gp;
	mbedtls_rsa_context rsa_ctx;
	
	//For sanity sake all components listed! Clarify implementation.
	TEE_Attribute *rsa_public_exp = NULL;
	TEE_Attribute *rsa_private_exp = NULL;
	TEE_Attribute *rsa_modulus = NULL;
	TEE_Attribute *rsa_prime1 = NULL;
	TEE_Attribute *rsa_prime2 = NULL;
	TEE_Attribute *rsa_exponent1 = NULL;
	TEE_Attribute *rsa_exponent2 = NULL;
	TEE_Attribute *rsa_coefficient = NULL;

	mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;

	//Convinience variables
	TEE_Attribute *attrs = NULL;
	uint32_t attrs_count = 0;

	attrs = key->gp_attrs.attrs;
	attrs_count = key->gp_attrs.attrs_count;

	usr_rsa_public_exp = get_attr_from_attrArr(TEE_ATTR_RSA_PUBLIC_EXPONENT, params, paramCount);
	rsa_public_exp = get_attr_from_attrArr(TEE_ATTR_RSA_PUBLIC_EXPONENT, attrs, attrs_count);
	rsa_private_exp = get_attr_from_attrArr(TEE_ATTR_RSA_PRIVATE_EXPONENT, attrs, attrs_count);
	rsa_modulus = get_attr_from_attrArr(TEE_ATTR_RSA_MODULUS, attrs, attrs_count);
	rsa_prime1 = get_attr_from_attrArr(TEE_ATTR_RSA_PRIME1, attrs, attrs_count);
	rsa_prime2 = get_attr_from_attrArr(TEE_ATTR_RSA_PRIME2, attrs, attrs_count);
	rsa_exponent1 = get_attr_from_attrArr(TEE_ATTR_RSA_EXPONENT1, attrs, attrs_count);
	rsa_exponent2 = get_attr_from_attrArr(TEE_ATTR_RSA_EXPONENT2, attrs, attrs_count);
	rsa_coefficient = get_attr_from_attrArr(TEE_ATTR_RSA_COEFFICIENT, attrs, attrs_count);
	
	//Internal sanity check. We should have all attributes in key
	if (rsa_public_exp == NULL || rsa_private_exp == NULL ||
	    rsa_prime1 == NULL || rsa_prime2 == NULL || rsa_exponent1 == NULL ||
	    rsa_exponent2 == NULL || rsa_coefficient == NULL || rsa_modulus == NULL) {
		OT_LOG_ERR("ERROR: Internal RSA key generation error (1)");
		TEE_Panic(TEE_ERROR_GENERIC);
	}
	
	if (usr_rsa_public_exp) {
		if (usr_rsa_public_exp->content.ref.length > mbedtls_RSA_PUBLIC_EXP) {
			OT_LOG_ERR("ERROR: Internal RSA public exponent limitation "
				   "(provided[%lu]; maxPubExpSizeInBytes[%lu])",
				   usr_rsa_public_exp->content.ref.length, mbedtls_RSA_PUBLIC_EXP);
			rv_gp = TEE_ERROR_BAD_PARAMETERS;
			goto err_1;
		}

		memcpy(&pub_exp, usr_rsa_public_exp->content.ref.buffer, mbedtls_RSA_PUBLIC_EXP);
	} else {
		//Already 65537 initialized!
	}

	mbedtls_rsa_init(&rsa_ctx);
	rv_mbedtls = mbedtls_rsa_gen_key(&rsa_ctx, mbedtls_ctr_drbg_random,
					 &ot_mbedtls_ctr_drbg, keySize_u_int, pub_exp);
	if(rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("ERROR: Internal RSA key generation error (2)");
		rv_gp = TEE_ERROR_GENERIC;
		goto err_1;
	}

	mbedtls_mpi_init(&N);
	mbedtls_mpi_init(&P);
	mbedtls_mpi_init(&Q);
	mbedtls_mpi_init(&D);
	mbedtls_mpi_init(&E);
	mbedtls_mpi_init(&DP);
	mbedtls_mpi_init(&DQ);
	mbedtls_mpi_init(&QP);
	
	rv_mbedtls = mbedtls_rsa_export(&rsa_ctx, &N, &P, &Q, &D, &E);
	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("ERROR: Internal RSA key generation error (3)");
		rv_gp = TEE_ERROR_GENERIC;
		goto err_2;
	}

	rv_mbedtls = mbedtls_rsa_export_crt(&rsa_ctx, &DP, &DQ, &QP);
	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("ERROR: Internal RSA key generation error (4)");
		rv_gp = TEE_ERROR_GENERIC;
		goto err_2;
	}

	copy_attr2mbedtlsMpi(&N, rsa_modulus, key->key_max_length);
	copy_attr2mbedtlsMpi(&P, rsa_prime1, key->key_max_length);
	copy_attr2mbedtlsMpi(&Q, rsa_prime2, key->key_max_length);
	copy_attr2mbedtlsMpi(&D, rsa_private_exp, key->key_max_length);
	copy_attr2mbedtlsMpi(&E, rsa_public_exp, key->key_max_length);
	copy_attr2mbedtlsMpi(&DP, rsa_coefficient, key->key_max_length);
	copy_attr2mbedtlsMpi(&DQ, rsa_exponent1, key->key_max_length);
	copy_attr2mbedtlsMpi(&QP, rsa_exponent2, key->key_max_length);

	rv_gp = TEE_SUCCESS;
 err_1:
	mbedtls_rsa_free(&rsa_ctx);
 err_2:
	mbedtls_mpi_free(&N);
	mbedtls_mpi_free(&P);
	mbedtls_mpi_free(&Q);
	mbedtls_mpi_free(&D);
	mbedtls_mpi_free(&E);
	mbedtls_mpi_free(&DP);
	mbedtls_mpi_free(&DQ);
	mbedtls_mpi_free(&QP);

	return rv_gp;
}

static TEE_Result gen_ecc_keypair(struct gp_key *key,
				  uint32_t keySize, //IN BITS!
				  uint32_t ecc_type,
				  TEE_Attribute *params,
				  uint32_t paramCount)
{
	mbedtls_ecdsa_context ctx;
	mbedtls_ecp_group grp;
	int rv_mbedtls = 0;
	TEE_Result rv_gp = TEE_ERROR_GENERIC;
	mbedtls_mpi d, *d_ptr = NULL;
	mbedtls_ecp_point Q, *Q_ptr = NULL;

	TEE_Attribute *usr_curve = NULL;
	TEE_Attribute *curve = NULL;
	TEE_Attribute *private = NULL;
	TEE_Attribute *x = NULL;
	TEE_Attribute *y = NULL;
	
	mbedtls_ecdsa_init(&ctx);
	mbedtls_ecp_group_init(&grp);
	mbedtls_mpi_init(&d);
	mbedtls_ecp_point_init(&Q);
	
	usr_curve = get_attr_from_attrArr(TEE_ATTR_ECC_CURVE, params, paramCount);
	if (usr_curve == NULL) {
		OT_LOG_ERR("ECC key generation requires TEE_ATTR_ECC_CURVE parameter");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (valid_ecc_curve_and_keysize(usr_curve, keySize)) {
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	keySize = BITS2BYTE(keySize);
	
	if (keySize > key->key_max_length) {
		OT_LOG_ERR("Generated key does not fit into object (keySize[%u]; "
			   "maxKeySize[%u])", keySize, key->key_max_length);
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}
	
	curve = get_attr_from_attrArr(TEE_ATTR_ECC_CURVE, key->gp_attrs.attrs, key->gp_attrs.attrs_count);
	private = get_attr_from_attrArr(TEE_ATTR_ECC_PRIVATE_VALUE, key->gp_attrs.attrs, key->gp_attrs.attrs_count);
	x = get_attr_from_attrArr(TEE_ATTR_ECC_PUBLIC_VALUE_X, key->gp_attrs.attrs, key->gp_attrs.attrs_count);
	y = get_attr_from_attrArr(TEE_ATTR_ECC_PUBLIC_VALUE_Y, key->gp_attrs.attrs, key->gp_attrs.attrs_count);

	if (curve == NULL || private == NULL || x == NULL || y == NULL) {
		OT_LOG(LOG_ERR, "Internal error: missing ECC key component");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	if (ecc_type == TEE_TYPE_ECDH_KEYPAIR) {
		rv_mbedtls = mbedtls_ecp_group_load(&grp, gp_curve2mbedtls(usr_curve->content.value.a));
		if (rv_mbedtls != 0) {
			print_mbedtls_to_syslog(rv_mbedtls);
			OT_LOG(LOG_ERR, "Internal crypto error: mbedtls curve load");
			rv_gp = TEE_ERROR_GENERIC;
			goto err;
		}
		
		rv_mbedtls = mbedtls_ecdh_gen_public(&grp, &d, &Q,
						     mbedtls_ctr_drbg_random,
						     &ot_mbedtls_ctr_drbg);
		if (rv_mbedtls != 0) {
			print_mbedtls_to_syslog(rv_mbedtls);
			OT_LOG(LOG_ERR, "Internal crypto error: ECDH key generation");
			rv_gp = TEE_ERROR_GENERIC;
			goto err;
		}

		Q_ptr = &Q;
		d_ptr = &d;
		
	} else if (ecc_type == TEE_TYPE_ECDSA_KEYPAIR) {
		rv_mbedtls = mbedtls_ecdsa_genkey(&ctx,
						  gp_curve2mbedtls(usr_curve->content.value.a),
						  mbedtls_ctr_drbg_random,
						  &ot_mbedtls_ctr_drbg);
		if (rv_mbedtls != 0) {
			print_mbedtls_to_syslog(rv_mbedtls);
			OT_LOG(LOG_ERR, "Internal crypto error: ECDSA key generation");
			rv_gp = TEE_ERROR_GENERIC;
			goto err;
		}

		Q_ptr = &ctx.private_Q;
		d_ptr = &ctx.private_d;
	} else {
		
		OT_LOG(LOG_ERR, "Not support type");
		TEE_Panic(TEE_ERROR_GENERIC);
	}
	
	copy_attr2mbedtlsMpi(&Q_ptr->private_Y, y, key->key_max_length);
	copy_attr2mbedtlsMpi(&Q_ptr->private_X, x, key->key_max_length);
	copy_attr2mbedtlsMpi(d_ptr, private, key->key_max_length);
	curve->content.value.a = usr_curve->content.value.a;
	
	rv_gp = TEE_SUCCESS;
 err:
	mbedtls_mpi_free(&d);
	mbedtls_ecp_point_free(&Q);
	mbedtls_ecp_group_free(&grp);
	mbedtls_ecdsa_free(&ctx);
	return rv_gp;
}





/*
 * GP Transient API
 */

TEE_Result TEE_AllocateTransientObject(uint32_t objectType,
				       uint32_t maxObjectSize,
				       TEE_ObjectHandle *object)
{
	if (object == NULL) {
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	*object = 0;

	if (valid_object_type_and_max_size(objectType, maxObjectSize)) {
		OT_LOG_ERR("TEE_AllocateTransientObject not supported objectType"
			   " [%u] OR/AND objectMaxSize [%u]", objectType, maxObjectSize);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	// Alloc memory for objectHandle
	*object = (TEE_ObjectHandle)calloc(1, sizeof(struct __TEE_ObjectHandle));
	if (*object == NULL) {
		OT_LOG_ERR("Malloc failed\n");
		goto out_of_mem_1;
	}

	if (objectType != TEE_TYPE_DATA) {
		if (malloc_gp_key_struct(&(*object)->key, objectType, BITS2BYTE(maxObjectSize))) {
			goto out_of_mem_2; //Error msg printed
		}
	}
	
	/* object info */
	(*object)->objectInfo.objectUsage = 0xFFFFFFFF;
	(*object)->objectInfo.maxObjectSize = maxObjectSize;
	(*object)->objectInfo.objectType = objectType;
	(*object)->objectInfo.keySize = 0;
	(*object)->objectInfo.dataSize = 0;
	(*object)->objectInfo.handleFlags = 0x00000000;

	return TEE_SUCCESS;

out_of_mem_2:
	free(*object);
out_of_mem_1:
	*object = 0;
	return TEE_ERROR_OUT_OF_MEMORY;
}

void TEE_FreeTransientObject(TEE_ObjectHandle object)
{
	if (object == NULL) {
		return;
	}
	
	if (object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) {
		OT_LOG_ERR("TEE_FreeTransientObject panics due trying to free persistant object\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	free_object_handle(object);
}

void TEE_ResetTransientObject(TEE_ObjectHandle object)
{
	if (object == NULL) {
		return;
	}

	if (object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) {
		OT_LOG_ERR("Panicking due trying to reset persitant object");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Reset info */
	object->objectInfo.objectUsage = 0xFFFFFFFF;
	object->objectInfo.keySize = 0;
	object->objectInfo.dataSize = 0;
	object->objectInfo.handleFlags = 0x00000000;

	/* Note: Breaking GP compatibility. Can't reuse the key, because it
	 * might be used by operation. We need to malloc new gp key struct for object
	 *
	 * Clarify: We should not malloc a new key, because this function should
	 * not fail */

	free_gp_key(object->key);

	if (malloc_gp_key_struct(&object->key,
				 object->objectInfo.objectType,
				 object->objectInfo.maxObjectSize)) {
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY); //Error msg printed
	}
}

TEE_Result TEE_PopulateTransientObject(TEE_ObjectHandle object,
				       TEE_Attribute *attrs,
				       uint32_t attrCount)
{
	TEE_Result ret = TEE_SUCCESS;

	if (object == NULL) {
		OT_LOG_ERR("TEE_PopulateTransientObject panics due object NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (attrs == NULL) {
		OT_LOG_ERR("TEE_PopulateTransientObject panics due attrs NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (object->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) {
		OT_LOG_ERR("TEE_PopulateTransientObject panics due trying "
			   "to populate initilized object");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) {
		OT_LOG_ERR("TEE_PopulateTransientObject panics due trying to "
			   "populate persistant object (persistant object always initialzed)");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}
	
	switch (object->objectInfo.objectType) {
	case TEE_TYPE_AES:
	case TEE_TYPE_HMAC_MD5:
	case TEE_TYPE_HMAC_SHA1:
	case TEE_TYPE_HMAC_SHA224:
	case TEE_TYPE_HMAC_SHA256:
	case TEE_TYPE_HMAC_SHA384:
	case TEE_TYPE_HMAC_SHA512:
		ret = populate_secret_key(attrs, attrCount, object->key);
		break;

	case TEE_TYPE_RSA_PUBLIC_KEY:
	case TEE_TYPE_RSA_KEYPAIR:
		ret = populate_rsa_key(attrs, attrCount, object->key, object->objectInfo.objectType);
		break;

	case TEE_TYPE_ECDH_KEYPAIR:
	case TEE_TYPE_ECDH_PUBLIC_KEY:
	case TEE_TYPE_ECDSA_KEYPAIR:
	case TEE_TYPE_ECDSA_PUBLIC_KEY:
		ret = populate_ecc_key(attrs, attrCount, object->key, object->objectInfo.objectType);
		break;
		
	default:
		OT_LOG(LOG_ERR, "Not supported object type [%u]\n", object->objectInfo.objectType);
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	if (ret == TEE_SUCCESS) {
		object->objectInfo.handleFlags |= TEE_HANDLE_FLAG_INITIALIZED;
		object->key->reference_count++;
		object->objectInfo.keySize = keysize_in_bits(object->key->key_lenght);
	}

	return ret;
}

void TEE_InitRefAttribute(TEE_Attribute *attr,
			  uint32_t attributeID,
			  void *buffer,
			  size_t length)
{
	if (attr == NULL || is_value_attribute(attributeID)) {
		OT_LOG_ERR("Panicking due attribute null OR not a reference attribute\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	attr->attributeID = attributeID;
	attr->content.ref.buffer = buffer;
	attr->content.ref.length = length;
}

void TEE_InitValueAttribute(TEE_Attribute *attr,
			    uint32_t attributeID,
			    uint32_t a,
			    uint32_t b)
{
	if (attr == NULL || !is_value_attribute(attributeID)) {
		OT_LOG_ERR("Panicking due attribute null OR not a VALUE attribute\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	attr->attributeID = attributeID;
	attr->content.value.a = a;
	attr->content.value.b = b;
}

void TEE_CopyObjectAttributes1(TEE_ObjectHandle destObject,
			       TEE_ObjectHandle srcObject)
{
	//TODO: Function
	
	//Disabling function due not tested and it is missing functionality
	
	OT_LOG(LOG_ERR, "TEE_CopyObjectAttributes1 not implemented");
	TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);
	
	if (destObject == NULL || srcObject == NULL) {
		OT_LOG_ERR("Panicking due destObject or srcObject NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (destObject->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED ||
	    !(srcObject->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED)) {
		OT_LOG(LOG_ERR, "Dest object initalized and source object is uninitialized\n");
		TEE_Panic(TEE_ERROR_BAD_STATE);
	}

	if (srcObject->objectInfo.maxObjectSize > destObject->objectInfo.maxObjectSize) {
		OT_LOG(LOG_ERR, "Problem with destination and source object size\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Copy attributes, if possible */
	if (destObject->objectInfo.objectType == srcObject->objectInfo.objectType) {

		if (TEE_SUCCESS != TEE_PopulateTransientObject(destObject,
							       srcObject->key->gp_attrs.attrs,
							       srcObject->key->gp_attrs.attrs_count))
			TEE_Panic(TEE_ERROR_GENERIC); /* Should never happen */

	} else if (destObject->objectInfo.objectType == TEE_TYPE_RSA_PUBLIC_KEY &&
		   srcObject->objectInfo.objectType == TEE_TYPE_RSA_KEYPAIR) {

		//TODO: Error. Extract only public part!

		if (TEE_SUCCESS != TEE_PopulateTransientObject(destObject,
							       srcObject->key->gp_attrs.attrs,
							       srcObject->key->gp_attrs.attrs_count))
			TEE_Panic(TEE_ERROR_GENERIC); /* Should never happen */

	} else if (destObject->objectInfo.objectType == TEE_TYPE_DSA_PUBLIC_KEY &&
		   srcObject->objectInfo.objectType == TEE_TYPE_DSA_KEYPAIR) {
		OT_LOG_ERR("Panicking due TEE_TYPE_DSA_PUBLIC_KEY and "
			   "TEE_TYPE_DSA_KEYPAIR not supported");
		TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED); /* Not yet */

	} else if (destObject->objectInfo.objectType == TEE_TYPE_ECDSA_PUBLIC_KEY &&
		   srcObject->objectInfo.objectType == TEE_TYPE_ECDSA_KEYPAIR) {
		OT_LOG_ERR("Panicking due TEE_TYPE_ECDSA_PUBLIC_KEY and "
			   "TEE_TYPE_ECDSA_KEYPAIR not supported");
		TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED); /* Not yet */

	} else {
		OT_LOG(LOG_ERR, "Error in copying attributes: Problem with compatibles\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Set object Info */
	destObject->objectInfo.handleFlags |= TEE_HANDLE_FLAG_INITIALIZED;
	destObject->objectInfo.handleFlags &= srcObject->objectInfo.handleFlags;
	destObject->objectInfo.keySize = BYTE2BITS(srcObject->key->key_lenght);
}

TEE_Result TEE_GenerateKey(TEE_ObjectHandle object,
			   uint32_t keySize,
			   TEE_Attribute *params,
			   uint32_t paramCount)
{
	TEE_Result ret = TEE_SUCCESS;

	// Should be a transient object and uninit
	if (object == NULL) {
		OT_LOG_ERR("TEE_GenerateKey panics due object NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (object->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) {
		OT_LOG_ERR("TEE_GenerateKey panics due already initialized");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) {
		OT_LOG_ERR("TEE_GenerateKey panics due persistant "
			   "object (persistant always initialized)");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (BITS2BYTE(keySize) > object->key->key_max_length) {
		OT_LOG_ERR("TEE_GenerateKey panics due key would not fit to object "
			   "(generatedKeySize[%u]; objectKeySize[%u])",
			   BITS2BYTE(keySize), object->key->key_max_length);
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}
	
	switch (object->objectInfo.objectType) {
	case TEE_TYPE_AES:
	case TEE_TYPE_HMAC_MD5:
	case TEE_TYPE_HMAC_SHA1:
	case TEE_TYPE_HMAC_SHA224:
	case TEE_TYPE_HMAC_SHA256:
	case TEE_TYPE_HMAC_SHA384:
	case TEE_TYPE_HMAC_SHA512:
	case TEE_TYPE_GENERIC_SECRET:
		ret = gen_symmetric_key(object->key, BITS2BYTE(keySize));
		break;

	case TEE_TYPE_RSA_KEYPAIR:
		ret = gen_rsa_keypair(object->key, BITS2BYTE(keySize), params, paramCount);
		break;

	case TEE_TYPE_ECDH_KEYPAIR:
	case TEE_TYPE_ECDSA_KEYPAIR:
		ret = gen_ecc_keypair(object->key, keySize,
				      object->objectInfo.objectType, params, paramCount);
		break;
	default:
		// Should never get here
		OT_LOG_ERR("TEE_GenerateKey panics due object type not supported "
			   "(objectType[%u])", object->objectInfo.objectType);
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	if (ret == TEE_SUCCESS) {
		object->objectInfo.handleFlags |= TEE_HANDLE_FLAG_INITIALIZED;
		object->objectInfo.keySize = keySize;
		object->key->reference_count++;
		object->key->key_lenght = BITS2BYTE(keySize);
	}

	return ret;
}
