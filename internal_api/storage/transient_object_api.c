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

#include <mbedtls/ctr_drbg.h>
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
#include "opentee_storage_common.h"
#include "crypto/crypto_utils.h"

/*
static TEE_Attribute *get_attr_from_attrArr(uint32_t ID,
					    TEE_Attribute *attrs,
					    uint32_t attrCount)
{
	uint32_t i;

	if (attrs == NULL)
		return (TEE_Attribute *)NULL;

	for (i = 0; i < attrCount; ++i) {
		if (ID == attrs[i].attributeID) 
			return &attrs[i];
	}
	
	return (TEE_Attribute *)NULL;
}
*/

static int malloc_attr(TEE_Attribute *init_attr,
		       uint32_t attrID,
		       uint32_t buf_len)
{
	init_attr->content.ref.buffer = calloc(1, buf_len);
	if (init_attr->content.ref.buffer == NULL) {
		OT_LOG_ERR("Malloc failed");
		return 1;
	}
	
	init_attr->content.ref.length = 0; //Nothing initilaized
	init_attr->attributeID = attrID;

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
	
	if (gp_attr == NULL || is_value_attribute(gp_attr->attributeID)) {
		OT_LOG(LOG_ERR, "No GP key attribute to copy or value "
		       "attribute (cpy_attr[%u])", cpy_attr->attributeID);
		TEE_Panic(TEE_ERROR_GENERIC); /* Should never happen */
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

/*
static TEE_Result populate_rsa_key(TEE_Attribute *attrs,
				   uint32_t attrCount,
				   struct gp_key *key)
{
	//TODO: Add private key and parameters checks
	
	TEE_Attribute *modulo = 0, *public_exp = 0, *private_exp = 0, *prime1 = 0,
		*prime2 = 0, *coff = 0, *exp1 = 0, *exp2 = 0, *correspond_gp_key_attr = 0;
	int rv_mbedtls;
	uint32_t rsa_max_comp_size;
	mbedtls_rsa_context rsa_ctx;
	
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

	// Common for public and rsa key pair
	if (modulo == NULL || public_exp == NULL) {
		OT_LOG_ERR("Panicking due missing RSA key TEE_ATTR_RSA_MODULUS or "
			   "TEE_ATTR_RSA_PUBLIC_EXPONENT");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (modulo->content.ref.length > key->key_max_length) {
		OT_LOG_ERR("Panicking due RSA key too big: reserved size [%u]; "
			   "provided size [%u]",key->key_max_length, modulo->content.ref.length);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (public_exp->content.ref.length > mbedtls_RSA_PUBLIC_EXP) {
		OT_LOG_ERR("Panics due TEE_ATTR_RSA_PUBLIC_EXPONENT too big. "
			   "OpenTEE limits public exponent to 4 bytes!");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}
	
	rsa_max_comp_size = mbedtls_RSA_LONGEST_COMPONENT(key->key_max_length);
	
	if (key->gp_key_type == TEE_TYPE_RSA_KEYPAIR) {

		if (private_exp == NULL) {
			OT_LOG_ERR("Panicking due missing RSA key TEE_ATTR_RSA_PRIVATE_EXPONENT");
			TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
		}

		if (private_exp->content.ref.length > rsa_max_comp_size) {
			OT_LOG_ERR("Panicking due private exponent size mismatch: "
				   "reserved size [%u]; provided size [%u]\n",
				   private_exp->content.ref.length,
				   mbedtls_RSA_PRIVATE_EXP(modulo->content.ref.length));
			return TEE_ERROR_BAD_PARAMETERS;
		}
		
		if (prime1 || prime2 || coff || exp1 || exp2) {
			
			if (prime1 == NULL  || prime2 == NULL  || coff == NULL  ||
			    exp1 == NULL  || exp2 == NULL) {
				OT_LOG_ERR("Panicking due missing RSA component "
					   "(need to provide all or none)");
				TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
			}

			if (prime1->content.ref.length > rsa_max_comp_size ||
			    prime2->content.ref.length > rsa_max_comp_size ||
			    exp1->content.ref.length > rsa_max_comp_size ||
			    exp2->content.ref.length > rsa_max_comp_size ||
			    coff->content.ref.length > rsa_max_comp_size) {
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

	if (modulo && public_exp) {
		
		rv_mbedtls = mbedtls_rsa_import_raw(&key->key.rsa.ctx,
						    modulo->content.ref.buffer, modulo->content.ref.length,
						    NULL, 0, //prime1
						    NULL, 0, //prime2
						    NULL, 0, //Private exp
						    public_exp->content.ref.buffer, public_exp->content.ref.length);
	} else if (modulo && public_exp && private_exp) {
		rv_mbedtls = mbedtls_rsa_import_raw(&key->key.rsa.ctx,
						    modulo->content.ref.buffer, modulo->content.ref.length,
						    NULL, 0, //prime1
						    NULL, 0, //prime2
						    private_exp->content.ref.buffer, private_exp->content.ref.length,
						    public_exp->content.ref.buffer, public_exp->content.ref.length);
	} else if (modulo && public_exp && private_exp && prime1 && prime2) {
		rv_mbedtls = mbedtls_rsa_import_raw(&key->key.rsa.ctx,
						    modulo->content.ref.buffer, modulo->content.ref.length,
						    prime1->content.ref.buffer, prime1->content.ref.length,
						    prime2->content.ref.buffer, prime2->content.ref.length,
						    private_exp->content.ref.buffer, private_exp->content.ref.length,
						    public_exp->content.ref.buffer, public_exp->content.ref.length);
	} else {
		OT_LOG(LOG_ERR, "Not supported combination");
		TEE_Panic(TEE_ERROR_GENERIC);
	}
		
	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("ERROR: internal crypto error (RSA importing)");
		goto err;
	}

	rv_mbedtls = mbedtls_rsa_complete(&key->key.rsa.ctx);
	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("ERROR: internal crypto error (RSA key population)");
		goto err;
	}
	
	rv_mbedtls = mbedtls_rsa_check_pubkey(&key->key.rsa.ctx);
	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("ERROR: internal crypto error (RSA key population; public key)");
		goto err;
	}
	
	if (key->gp_key_type == TEE_TYPE_RSA_KEYPAIR) {
		rv_mbedtls = mbedtls_rsa_check_pubkey(&key->key.rsa.ctx);
		if (rv_mbedtls != 0) {
			print_mbedtls_to_syslog(rv_mbedtls);
			OT_LOG_ERR("ERROR: internal crypto error (RSA key population; private key)");
			goto err;
		}
	}

	//Key is OK. Copy attributes to key.
	copy_attr2gpKeyAttr(key, modulo);
	copy_attr2gpKeyAttr(key, public_exp);
	copy_attr2gpKeyAttr(key, prime1);
	copy_attr2gpKeyAttr(key, prime2);
	copy_attr2gpKeyAttr(key, exp1);
	copy_attr2gpKeyAttr(key, exp2);
	copy_attr2gpKeyAttr(key, coff);
	copy_attr2gpKeyAttr(key, private_exp);
	
	key->key_lenght = modulo->content.ref.length;

	return TEE_SUCCESS;

 err:
	return TEE_ERROR_GENERIC;
}
*/
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

static int malloc_ecdsa_attrs(struct gp_key *key,
			      uint32_t objectType,
			      uint32_t maxObjectSize)
{
	//TODO

	key = key;
	objectType = objectType;
	maxObjectSize = maxObjectSize;
	
	TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);

	return 0;
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
		OT_LOG_ERR("Malloc failed\n");
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
		if (malloc_ecdsa_attrs(*key, objectType, maxObjectSize)) {
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
