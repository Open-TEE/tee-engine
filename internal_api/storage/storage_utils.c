/*****************************************************************************
** Copyright (C) 2015 Open-TEE project.					    **
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

#include "object_handle.h"
#include "storage_utils.h"
#include "tee_logging.h"
#include "opentee_internal_api.h"
#include "crypto/operation_handle.h"
#include "tee_panic.h"
#include "tee_storage_api.h"
#include "tee_time_api.h"

void __attribute__((unused)) pri_buf_hex_format(const char *title,
						       const unsigned char *buf,
						       int buf_len)
{
	char hex[10];
	char hexstr[5000];
	int i;

	if (buf == NULL) {
		OT_LOG_ERR("pri_buf_hex_format: NULL");
		return;
	}
	
	memset(hexstr, 0, 5000);
	
	OT_LOG_ERR("%s [%u]:", title, buf_len);
	for (i = 0; i < buf_len; ++i) {
		sprintf(hex, "%02X-", buf[i]);
		strcat(hexstr, hex);
		//		if ((i % 32) == 0)
		//	OT_LOG_ERR("\n");

		//OT_LOG_ERR("%02x %02x", buf[i], buf[i+1]);
	}
	OT_LOG_ERR("%s",hexstr);
	//OT_LOG_ERR("\n");
}


static bool multiple_of_8(uint32_t number)
{
	return !(number % 8) ? true : false;
}

static bool multiple_of_64(uint32_t number)
{
	return !(number % 64) ? true : false;
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
		if (obj_size >= 80 && obj_size <= 512 && multiple_of_8(obj_size))
			return 0;
		return 1;

	case TEE_TYPE_HMAC_SHA1:
		if (obj_size >= 112 && obj_size <= 512 && multiple_of_8(obj_size))
			return 0;
		return 1;

	case TEE_TYPE_HMAC_SHA224:
		if (obj_size >= 192 && obj_size <= 512 && multiple_of_8(obj_size))
			return 0;
		return 1;

	case TEE_TYPE_HMAC_SHA256:
		if (obj_size >= 256 && obj_size <= 1024 && multiple_of_8(obj_size))
			return 0;
		return 1;

	case TEE_TYPE_HMAC_SHA384:
		if (obj_size >= 64 && obj_size <= 1024 && multiple_of_8(obj_size))
			return 0;
		return 1;

	case TEE_TYPE_HMAC_SHA512:
		if (obj_size >= 64 && obj_size <= 1024 && multiple_of_8(obj_size))
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

	default:
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

	default:
		OT_LOG_ERR("Not supported TEE_TYPE_XXXXXX [%u]", obj_type);
		return 1;
	}

	return 0;
}
/*
void free_gp_attributes(TEE_Attribute *attrs. uint32_t attrs_count)
{
	uint32_t i;



	for (i = 0; i < gp_attrs->attrs_count; i++) {
		if (is_value_attribute(gp_attrs->attrs[i].attributeID)) {
			continue;
		} else {
			free(gp_attrs->attrs[i].content.ref.buffer);
		}
	}
}
*/
void free_gp_key(struct gp_key *key)
{
	if (key->reference_count != 0) {
		key->reference_count--;
	}

	if (key->reference_count) {
		return;
	}

	/* mbedtls RSA key */
	if (key->gp_key_type == TEE_TYPE_RSA_PUBLIC_KEY ||
	    key->gp_key_type == TEE_TYPE_RSA_KEYPAIR) {
		mbedtls_rsa_free(&key->key.rsa.ctx);
	} else if (key->gp_key_type == TEE_TYPE_AES) {
		//TODO: No key? Investiage.
	} else {
		OT_LOG_ERR("Not supported key [%u]\n", key->gp_key_type);

		//TODO: Uncomment when release_ss_file() moved away from this file
		//TEE_Panic(TEE_ERROR_GENERIC);
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


/*
//TODO: Move this function to manager/internal api common!
void release_ss_file(uint32_t ss_id)
{
	struct com_mgr_invoke_cmd_payload payload, returnPayload;
	struct com_mrg_close_persistent closeObject;

	payload.size = sizeof(struct com_mrg_close_persistent);
	payload.data = &closeObject;
	//	closeObject.ss_id = ss_id;

	//TEE_InvokeMGRCommand(TEE_TIMEOUT_INFINITE, COM_MGR_CMD_ID_CLOSE_OBJECT, &payload, &returnPayload);
}
*/
void release_and_delete_ss_file(FILE *ss_file,
				void *objectID,
				size_t objectIDLen)
{
	//release_ss_file(ss_file, objectID, objectIDLen);
	delete_ss_file(objectID, objectIDLen);
}

void delete_ss_file(void *objectID,
		    size_t objectIDLen)
{
	char broken_tee_name_with_path[MAX_SS_FILE_NAME_WITH_PATH];
	uint32_t broken_tee_name_with_path_len = MAX_SS_FILE_NAME_WITH_PATH;
	char broken_tee_name[MAX_broken_tee_SS_FILE_LENGTH];
	uint32_t broken_tee_name_len = MAX_broken_tee_SS_FILE_LENGTH;
	/*
	if (map_gpID2broken_teeFileName(objectID, objectIDLen, (void *)broken_tee_name, &broken_tee_name_len))
		return;

	if (concat_path_and_name(broken_tee_name, broken_tee_name_len, broken_tee_name_with_path, MAX_SS_FILE_NAME_WITH_PATH))
		return;
*/
	remove(broken_tee_name_with_path);
}

TEE_Result get_broken_tee_ss_file_name_with_path(void *objectID,
						 size_t objectIDLen,
						 char *broken_tee_name_with_path,
						 uint32_t broken_tee_name_with_path_len)
{
	char broken_tee_name[MAX_broken_tee_SS_FILE_LENGTH];
	uint32_t broken_tee_name_len = MAX_broken_tee_SS_FILE_LENGTH;
	/*
	if (map_gpID2broken_teeFileName(objectID, objectIDLen, (void *)broken_tee_name, &broken_tee_name_len))
		return TEE_ERROR_STORAGE_NO_SPACE;

	if (concat_path_and_name(broken_tee_name, broken_tee_name_len, broken_tee_name_with_path, broken_tee_name_with_path_len))
		return TEE_ERROR_GENERIC;
*/
	return TEE_SUCCESS;
}
