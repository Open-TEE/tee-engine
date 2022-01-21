/*****************************************************************************
** Copyright (C) 2015 Open-TEE project.					    **
** Copyright (C) 2015-2021 Tanel Dettenborn                                 **
** Copyright (C) 2015-2021 Brian McGillion                                  **
** Copyright (C) 2022 Technology Innovation Institute (TII)                 **
**									    **
** Licensed under the Apache License, Version 2.0 (the "License");	    **
** you may not use this file except in compliance with the License.	    **
** You may obtain a copy of the License at				    **
**									    **
**	http://www.apache.org/licenses/LICENSE-2.0			    **
**									    **
** Unless required by applicable law or agreed to in writing, software	    **
** distributed under the License is distributed on an "AS IS" BASIS,	    **
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. **
** See the License for the specific language governing permissions and	    **
** limitations under the License.					    **
*****************************************************************************/

#include <mbedtls/rsa.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "object_handle.h"
#include "storage_utils.h"
#include "tee_logging.h"
#include "tee_storage_api.h"
#include "opentee_internal_api.h"
#include "crypto/operation_handle.h"
#include "tee_panic.h"
#include "tee_storage_api.h"
#include "tee_time_api.h"


static bool multiple_of_8(uint32_t number)
{
	return !(number % 8) ? true : false;
}

static bool multiple_of_64(uint32_t number)
{
	return !(number % 64) ? true : false;
}

void free_gp_attributes(struct gp_attributes *gp_attr)
{
	uint32_t i;

	if (gp_attr == NULL) {
		return;
	}

	if (gp_attr->attrs == NULL) {
		return;
	}

	for (i = 0; i < gp_attr->attrs_count; i++) {
		// Zero is illegal attributeID.
		if (gp_attr->attrs[i].attributeID == 0) {
			//We might jump out, but this function supports
			//middle alloc free
			continue;
		}

		if (is_value_attribute(gp_attr->attrs[i].attributeID)) {
			continue;
		} else {
			free(gp_attr->attrs[i].content.ref.buffer);
		}
	}

	free(gp_attr->attrs);
}

uint32_t keysize_in_bits(uint32_t key_in_bytes)
{
	//TODO: Move to "common between storage/crypto"
	//TODO: Overflow check.
	return key_in_bytes * 8; 
}

int keysize_in_bytes(uint32_t key_in_bits)
{
	//TODO: Move to "common between storage/crypto"
	if (key_in_bits <= UINT_MAX - 7)
		key_in_bits += 7;

	return key_in_bits / 8;
}

TEE_Attribute *get_attr_from_attrArr(uint32_t ID,
				     TEE_Attribute *attrs,
				     uint32_t attrCount)
{
	uint32_t i;

	if (attrs == NULL)
		return (TEE_Attribute *)NULL;

	for (i = 0; i < attrCount; ++i) {
		if (ID == attrs[i].attributeID) {
			return &attrs[i];
		}
	}

	return (TEE_Attribute *)NULL;
}

void close_persistan_object(void *objectID, uint32_t objectIDLen)
{
	struct com_mgr_invoke_cmd_payload payload, returnPayload;
	struct com_mrg_close_persistent *closeObject;

	payload.size = sizeof(struct com_mrg_close_persistent);
	payload.data = calloc(1, payload.size);
	if (payload.data == NULL) {
		OT_LOG_ERR("Out of memory");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	closeObject = payload.data;
	memcpy(((struct com_mrg_close_persistent *)payload.data)->objectID, (uint8_t *)objectID, objectIDLen);
	closeObject->objectIDLen = objectIDLen;

	TEE_InvokeMGRCommand(TEE_TIMEOUT_INFINITE, COM_MGR_CMD_ID_CLOSE_OBJECT, &payload, &returnPayload);

	free(payload.data);
}


int valid_object_type_and_max_size(uint32_t obj_type,
				   uint32_t obj_size)
{
	switch (obj_type) {
	case TEE_TYPE_AES:
		if (obj_size == 128 || obj_size == 192 || obj_size == 256)
			return 0;
		return 1;

	case TEE_TYPE_DES:
		if (obj_size == 56)
			return 0;
		return 1;

	case TEE_TYPE_DES3:
		if (obj_size == 112 || obj_size == 168)
			return 0;
		return 1;

	case TEE_TYPE_HMAC_MD5:
		if (obj_size >= 64 && obj_size <= 512 && multiple_of_8(obj_size))
			return 0;
		return 1;

	case TEE_TYPE_HMAC_SHA1:
		if (obj_size >= 80 && obj_size <= 512 && multiple_of_8(obj_size))
			return 0;
		return 1;

	case TEE_TYPE_HMAC_SHA224:
		if (obj_size >= 112 && obj_size <= 512 && multiple_of_8(obj_size))
			return 0;
		return 1;

	case TEE_TYPE_HMAC_SHA256:
		if (obj_size >= 192 && obj_size <= 1024 && multiple_of_8(obj_size))
			return 0;
		return 1;

	case TEE_TYPE_HMAC_SHA384:
		if (obj_size >= 256 && obj_size <= 1024 && multiple_of_8(obj_size))
			return 0;
		return 1;

	case TEE_TYPE_HMAC_SHA512:
		if (obj_size >= 256 && obj_size <= 1024 && multiple_of_8(obj_size))
			return 0;
		return 1;

	case TEE_TYPE_RSA_PUBLIC_KEY:
		if (obj_size >= 256 && obj_size <= 2048)
			return 0;
		return 1;

	case TEE_TYPE_RSA_KEYPAIR:
		if (obj_size >= 256 && obj_size <= 2048)
			return 0;
		return 1;

	case TEE_TYPE_DSA_PUBLIC_KEY:
		if (obj_size >= 512 && obj_size <= 1024 && multiple_of_64(obj_size))
			return 0;
		return 1;

	case TEE_TYPE_DSA_KEYPAIR:
		if (obj_size >= 512 && obj_size <= 1024 && multiple_of_64(obj_size))
			return 0;
		return 1;

	case TEE_TYPE_DH_KEYPAIR:
		if (obj_size >= 256 && obj_size <= 2048)
			return 0;
		return 1;

	case TEE_TYPE_GENERIC_SECRET:
		if (obj_size >= 8 && obj_size <= 4096 && multiple_of_8(obj_size))
			return 0;
		return 1;

	case TEE_TYPE_DATA:
		if (obj_size == 0)
			return 0;
		return 1;

	case TEE_TYPE_ECDH_KEYPAIR:
	case TEE_TYPE_ECDH_PUBLIC_KEY:
	case TEE_TYPE_ECDSA_PUBLIC_KEY:
	case TEE_TYPE_ECDSA_KEYPAIR:
		if (obj_size == 192 || obj_size == 224 ||
		    obj_size == 256 || obj_size == 384 ||
		    obj_size == 521) {
			return 0;
		}
		OT_LOG_ERR("OpenTEE supports following sizes for ECC 192, 224, 256, 384, 521");
		return 1;
	default:
		OT_LOG(LOG_ERR, "Not supported type [%u]", obj_type);
		return 1;
	}
}

int is_value_attribute(uint32_t attr_ID)
{
	/* Bit [29]:
	 * 0: buffer attribute
	 * 1: value attribute
	 * TEE_ATTR_FLAG_VALUE == 0x20000000
	 */
	return attr_ID & TEE_ATTR_FLAG_VALUE;
}

int expected_object_attr_count(uint32_t obj_type,
			       uint32_t *expected_attr_count)
{
	switch (obj_type) {
	case TEE_TYPE_AES:
	case TEE_TYPE_DES:
	case TEE_TYPE_DES3:
	case TEE_TYPE_HMAC_MD5:
	case TEE_TYPE_HMAC_SHA1:
	case TEE_TYPE_HMAC_SHA224:
	case TEE_TYPE_HMAC_SHA256:
	case TEE_TYPE_HMAC_SHA384:
	case TEE_TYPE_HMAC_SHA512:
	case TEE_TYPE_GENERIC_SECRET:
		*expected_attr_count = 1;
		break;

	case TEE_TYPE_RSA_PUBLIC_KEY:
		*expected_attr_count = 2;
		break;

	case TEE_TYPE_RSA_KEYPAIR:
		*expected_attr_count = 8;
		break;

	case TEE_TYPE_DSA_PUBLIC_KEY:
		*expected_attr_count = 4;
		break;

	case TEE_TYPE_DSA_KEYPAIR:
	case TEE_TYPE_DH_KEYPAIR:
		*expected_attr_count = 5;
		break;

	case TEE_TYPE_ECDH_PUBLIC_KEY:
	case TEE_TYPE_ECDSA_PUBLIC_KEY:
		*expected_attr_count = 3;
		break;

	case TEE_TYPE_ECDH_KEYPAIR:
	case TEE_TYPE_ECDSA_KEYPAIR:
		*expected_attr_count = 4;
		break;
	default:
		OT_LOG(LOG_ERR, "Not supported TEE_TYPE_XXXXXX [%u]", obj_type);
		return 1;
	}

	return 0;
}

void free_gp_key(struct gp_key *key)
{
	if (key->reference_count != 0) {
		key->reference_count--;
	}

	if (key->reference_count) {
		return;
	}

	// mbedtls RSA key
	if (key->gp_key_type == TEE_TYPE_RSA_PUBLIC_KEY ||
	    key->gp_key_type == TEE_TYPE_RSA_KEYPAIR) {
		//Nothing
	} else if (key->gp_key_type == TEE_TYPE_AES) {
		//TODO: No key? Investiage.
	} else if (key->gp_key_type == TEE_TYPE_HMAC_MD5 ||
		   key->gp_key_type == TEE_TYPE_HMAC_SHA1 ||
		   key->gp_key_type == TEE_TYPE_HMAC_SHA224 ||
		   key->gp_key_type == TEE_TYPE_HMAC_SHA256 ||
		   key->gp_key_type == TEE_TYPE_HMAC_SHA384 ||
		   key->gp_key_type == TEE_TYPE_HMAC_SHA512) {
		//TODO: Nothing?
	} else if (key->gp_key_type == TEE_TYPE_ECDSA_PUBLIC_KEY ||
		  key->gp_key_type == TEE_TYPE_ECDSA_KEYPAIR ||
		  key->gp_key_type == TEE_TYPE_ECDH_KEYPAIR ||
		  key->gp_key_type == TEE_TYPE_ECDH_PUBLIC_KEY) {
		//Nothing
	} else if (key->gp_key_type == TEE_TYPE_GENERIC_SECRET) {
		//Nothing
	} else {
		OT_LOG(LOG_ERR, "Not supported key [%u]\n", key->gp_key_type);
		
		//TODO: Uncomment when release_ss_file() moved away from this file
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	free_gp_attributes(&key->gp_attrs);
	free(key);
}

void free_object_handle(TEE_ObjectHandle object)
{
	if (object == NULL) {
		return;
	}

	if (object->key) {
		free_gp_key(object->key);
	}

	free(object);
	object = 0;
}
