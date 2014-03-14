/*****************************************************************************
** Copyright (C) 2013 ICRI.                                                 **
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

#define _GNU_SOURCE

#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>

#include <sys/stat.h>
#include <limits.h>
#include <stdio.h>
#include <syslog.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>

#include "storage_data_key_api.h"
#include "tee_memory.h"

struct __TEE_ObjectHandle {
	TEE_ObjectInfo objectInfo;
	TEE_Attribute *attrs;
	uint32_t attrs_count;
	uint32_t maxObjSizeBytes;
	char per_obj_id[TEE_OBJECT_ID_MAX_LEN + 1];
	size_t per_obj_id_len;
	FILE* per_obj_file_handler;
	long data_begin;
};

struct persistant_object {
	TEE_ObjectInfo info;
	uint32_t attrs_count;
	char per_obj_id[TEE_OBJECT_ID_MAX_LEN + 1];
	size_t obj_id_len;
};

struct __TEE_ObjectEnumHandle {
	DIR *dir;
};

#ifndef SECURE_STORAGE_PATH
#define SECURE_STORAGE_PATH "/home/dettenbo/TEE_secure_storage/"
#endif

static const uint32_t EMU_ALL = 0xF000001F;

static void free_attrs(TEE_ObjectHandle object);
static bool is_value_attribute(uint32_t attr_ID);
static int get_attr_index(TEE_ObjectHandle object, uint32_t attributeID);


/*
 * ## Non internal API functions ##
 */
static int is_directory_empty(char *dir_path)
{
	struct dirent *entry;
	int file_count = 0;
	DIR *dir = opendir(dir_path);
	if (dir == NULL)
		return 0;
	while ((entry = readdir(dir)) != NULL) {
		++file_count;
		if(file_count > 2) {
			closedir(dir);
			return 0;
		}
	}

	closedir(dir);
	return 1; //Directory Empty
}

static void get_uuid(char *uuid)
{
	char UUID_test[]  = "123456789012345"; /* For testing */
	memcpy(uuid, UUID_test, sizeof(TEE_UUID));
}

static void openssl_cleanup()
{
	CRYPTO_cleanup_all_ex_data();
}

static TEE_Result load_attributes(TEE_ObjectHandle obj)
{
	size_t i;

	if (obj == NULL || obj->per_obj_file_handler == NULL) {
		syslog(LOG_ERR, "Something went wrong with persistant object attribute loading\n");
		return TEE_ERROR_GENERIC;
	}

	/* Alloc memory for attributes (pointers) */
	obj->attrs = TEE_Malloc(obj->attrs_count * sizeof(TEE_Attribute), 0);
	if (obj->attrs == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	for (i = 0; i < obj->attrs_count; ++i) {
		if (fread(&obj->attrs[i], sizeof(TEE_Attribute), 1, obj->per_obj_file_handler) != 1)
			goto err_at_read;

		if (!is_value_attribute(obj->attrs[i].attributeID)) {
			obj->attrs[i].content.ref.buffer = TEE_Malloc(obj->maxObjSizeBytes, 0);
			if (obj->attrs[i].content.ref.buffer == NULL) {
				free_attrs(obj);
				free(obj->attrs);
				return TEE_ERROR_OUT_OF_MEMORY;
			}

			if (fread(obj->attrs[i].content.ref.buffer, obj->attrs[i].content.ref.length, 1, obj->per_obj_file_handler) != 1)
				goto err_at_read;
		}
	}

	return TEE_SUCCESS;

err_at_read:
	syslog(LOG_ERR, "Error at fwrite\n");
	free_attrs(obj);
	free(obj->attrs);
	return TEE_ERROR_GENERIC;
}

static void release_file(void* objectID, size_t objectIDLen)
{
	/* TEST!! Emulate/simulate manager call/return.. */
	objectID = objectID;
	objectIDLen = objectIDLen;
}


static FILE *query_for_access(void *objectID, size_t objectIDLen, size_t seek_access)
{
	static FILE* tmp_per_obj = NULL;
	seek_access = seek_access;
	char *name_with_dir_path;
	char *dir_path;
	size_t i;
	char hex_ID[TEE_OBJECT_ID_MAX_LEN * 2 + 1];
	char UUID[sizeof(TEE_UUID)];
	DIR *dir;

	get_uuid(UUID);
	printf("%s\n", UUID);

	for (i = 0; i < objectIDLen; ++i)
		sprintf(hex_ID + i * 2, "%02x", *((unsigned char*)objectID + i));

	if (asprintf(&dir_path, "%s%s", SECURE_STORAGE_PATH, UUID) == -1) {
		return NULL; // TEE_ERROR_OUT_OF_MEMORY;
	}

	if (asprintf(&name_with_dir_path, "%s%s/%s", SECURE_STORAGE_PATH, UUID, hex_ID) == -1) {
		free(dir_path);
		return NULL; // TEE_ERROR_OUT_OF_MEMORY;
	}

	if ((seek_access & TEE_DATA_FLAG_EXCLUSIVE) && (access(name_with_dir_path, F_OK) == 0)) {
		syslog(LOG_ERR, "Access conflict: File exists\n");
		goto ret;
	}

	/* Create secure storage directory */
	dir = opendir(SECURE_STORAGE_PATH);
	if (dir) {
		closedir(dir);
	}
	else if (ENOENT == errno) {
		if (mkdir(SECURE_STORAGE_PATH, 0777) != 0) {
			syslog(LOG_ERR, "Cannot create secure storage directory: %s\n", strerror(errno));
			goto ret;
		}
	}
	else {
		syslog(LOG_ERR, "Something went wrong in dir opening/creating\n");
		goto ret;
	}

	dir = opendir(dir_path);
	if (dir) {
		closedir(dir);
	}
	else if (ENOENT == errno) {
		if (mkdir(dir_path, 0777) != 0) {
			syslog(LOG_ERR, "Cannot create UUID directory: %s\n", strerror(errno));
			goto ret;
		}
	}
	else {
		syslog(LOG_ERR, "Something went wrong in dir opening/creating\n");
		goto ret;
	}

	if (seek_access & TEE_DATA_FLAG_ACCESS_WRITE_META || seek_access & TEE_DATA_FLAG_ACCESS_WRITE) {
		remove(name_with_dir_path); /* testing */
		tmp_per_obj = fopen(name_with_dir_path, "wb");
	}

	if (seek_access & TEE_DATA_FLAG_ACCESS_READ) {
		tmp_per_obj = fopen(name_with_dir_path, "rb");
	}

ret:
	free(name_with_dir_path);
	free(dir_path);
	return tmp_per_obj;
}

static void delete_file(void* objectID, size_t objectIDLen)
{
	char *name_with_dir_path;
	char *dir_path;
	size_t i;
	char hex_ID[TEE_OBJECT_ID_MAX_LEN * 2 + 1];
	char UUID[sizeof(TEE_UUID)];

	get_uuid(UUID);

	for (i = 0; i < objectIDLen; ++i)
		sprintf(hex_ID + i * 2, "%02x", *((unsigned char*)objectID + i));

	if (asprintf(&dir_path, "%s%s", SECURE_STORAGE_PATH, UUID) == -1) {
		return; // TEE_ERROR_OUT_OF_MEMORY;
	}

	if (asprintf(&name_with_dir_path, "%s%s/%s", SECURE_STORAGE_PATH, UUID, hex_ID) == -1) {
		free(dir_path);
		return; // TEE_ERROR_OUT_OF_MEMORY;
	}

	remove(name_with_dir_path);

	if (is_directory_empty(dir_path))
		rmdir(dir_path);

	free(name_with_dir_path);
	free(dir_path);
}

static FILE *is_object_id_in_use(TEE_ObjectHandle object, void *objectID, size_t objectIDLen)
{
	FILE *tmp_file;
	char *name_with_dir_path;
	char *new_name_with_dir_path;
	char hex_ID[TEE_OBJECT_ID_MAX_LEN * 2 + 1];
	char new_hex_ID[TEE_OBJECT_ID_MAX_LEN * 2 + 1];
	size_t i;
	char UUID[sizeof(TEE_UUID)];

	get_uuid(UUID);

	for (i = 0; i < object->per_obj_id_len; ++i)
		sprintf(hex_ID + i * 2, "%02x", *((unsigned char*)object->per_obj_id + i));

	for (i = 0; i < objectIDLen; ++i)
		sprintf(new_hex_ID + i * 2, "%02x", *((unsigned char*)objectID + i));

	if (asprintf(&name_with_dir_path, "%s%s/%s", SECURE_STORAGE_PATH, UUID, hex_ID) == -1) {
		return NULL; // TEE_ERROR_OUT_OF_MEMORY;
	}

	if (asprintf(&new_name_with_dir_path, "%s%s/%s", SECURE_STORAGE_PATH, UUID, new_hex_ID) == -1) {
		free(name_with_dir_path);
		return NULL; // TEE_ERROR_OUT_OF_MEMORY;
	}

	fclose(object->per_obj_file_handler);
	rename(name_with_dir_path, new_name_with_dir_path);

	if (object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_WRITE_META || object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_WRITE) {
		tmp_file = fopen(new_name_with_dir_path, "wb");
	}

	if (object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_READ) {
		tmp_file = fopen(new_name_with_dir_path, "rb");
	}

	free(name_with_dir_path);
	free(new_name_with_dir_path);
	return tmp_file;
}

static int does_arr_contain_attrID(uint32_t ID, TEE_Attribute* attrs, uint32_t attrCount)
{
	size_t i;

	for (i = 0; i < attrCount; ++i) {
		if (ID == attrs[i].attributeID)
			return i;
	}

	return -1;
}

static int copy_obj_attr_to_obj(TEE_ObjectHandle srcObj, uint32_t attrID, TEE_ObjectHandle destObj, uint32_t destIndex)
{
	int srcIndex = -1;
	uint32_t i;

	if (attrID == EMU_ALL) {
		for (i = 0; i < srcObj->attrs_count; i++) {
			memcpy(&destObj->attrs[i], &srcObj->attrs[i], sizeof(TEE_Attribute));

			if (!is_value_attribute(srcObj->attrs[i].attributeID)) {
				memcpy(destObj->attrs[i].content.ref.buffer, srcObj->attrs[i].content.ref.buffer, srcObj->attrs[i].content.ref.length);
				destObj->attrs[i].content.ref.length = srcObj->attrs[i].content.ref.length;
			}
		}

		return 1;
	}

	srcIndex = get_attr_index(srcObj, attrID);

	if (srcIndex == -1)
		return 0; /* Array does not contain extracted attribute */

	if (destIndex > destObj->attrs_count)
		return -1; /* Should never happen */

	memcpy(&destObj->attrs[destIndex], &srcObj->attrs[srcIndex], sizeof(TEE_Attribute));

	if (!is_value_attribute(srcObj->attrs[srcIndex].attributeID)) {
		memcpy(destObj->attrs[destIndex].content.ref.buffer, srcObj->attrs[srcIndex].content.ref.buffer, srcObj->attrs[srcIndex].content.ref.length);
		destObj->attrs[destIndex].content.ref.length = srcObj->attrs[srcIndex].content.ref.length;
	}

	return 1;
}

static int extract_attr_to_object(uint32_t ID, TEE_Attribute* params, uint32_t paramCount, TEE_ObjectHandle object, uint32_t index)
{
	int attr_index;

	attr_index = does_arr_contain_attrID(ID, params, paramCount);

	if (attr_index == -1)
		return 0; /* Array does not contain extracted attribute */

	if (index > object->attrs_count)
		return -1; /* Should never happen */

	memcpy(&object->attrs[index], &params[attr_index], sizeof(TEE_Attribute));

	if (!is_value_attribute(params[attr_index].attributeID)) {
		if (object->maxObjSizeBytes >= params[attr_index].content.ref.length) {
			memcpy(object->attrs[index].content.ref.buffer, params[attr_index].content.ref.buffer, params[attr_index].content.ref.length);
		}

		else {
			memcpy(object->attrs[index].content.ref.buffer, params[attr_index].content.ref.buffer, object->maxObjSizeBytes);
			object->attrs[index].content.ref.length = object->maxObjSizeBytes;
		}
	}

	return 1;
}

static int bn2ref_to_obj(BIGNUM *bn, uint32_t ID, TEE_ObjectHandle obj, int i)
{
	obj->attrs[i].content.ref.length = BN_num_bytes(bn);
	if (obj->attrs[i].content.ref.length > obj->maxObjSizeBytes)
		return -1;

	obj->attrs[i].attributeID = ID;
	BN_bn2bin(bn, obj->attrs[i].content.ref.buffer);
	return 1;
}

static int gen_10_key(TEE_ObjectHandle object, uint32_t keySize)
{
	if (!RAND_bytes(object->attrs->content.ref.buffer, keySize/8))
		return 0;

	object->attrs->attributeID = TEE_ATTR_SECRET_VALUE;
	object->attrs->content.ref.length = keySize / 8;

	return 1;
}

static int gen_rsa_keypair(TEE_ObjectHandle obj, uint32_t key_size)
{
	int i = 0;
	RSA *rsa_key = RSA_generate_key(key_size, RSA_3, NULL, NULL);

	if (rsa_key == NULL)
		return 0;

	if (!RSA_check_key(rsa_key)) {
		RSA_free(rsa_key);
		return 0;
	}

	/* Extract/copy values from RSA struct to object */

	if (bn2ref_to_obj(rsa_key->n, TEE_ATTR_RSA_MODULUS, obj, i++) == -1 ||
	    bn2ref_to_obj(rsa_key->e, TEE_ATTR_RSA_PUBLIC_EXPONENT, obj, i++) == -1 ||
	    bn2ref_to_obj(rsa_key->d, TEE_ATTR_RSA_PRIVATE_EXPONENT, obj, i++) == -1 ||
	    bn2ref_to_obj(rsa_key->p, TEE_ATTR_RSA_PRIME1, obj, i++) == -1 ||
	    bn2ref_to_obj(rsa_key->q, TEE_ATTR_RSA_PRIME2, obj, i++) == -1 ||
	    bn2ref_to_obj(rsa_key->dmp1, TEE_ATTR_RSA_EXPONENT1, obj, i++) == -1 ||
	    bn2ref_to_obj(rsa_key->dmq1, TEE_ATTR_RSA_EXPONENT2, obj, i++) == -1 ||
	    bn2ref_to_obj(rsa_key->iqmp, TEE_ATTR_RSA_COEFFICIENT, obj, i++) == -1) {
		RSA_free(rsa_key);
		return -1;
	}

	RSA_free(rsa_key);
	return 1;
}

static int gen_dsa_keypair(TEE_ObjectHandle object, TEE_Attribute* params, uint32_t paramCount)
{
	int i = 0, attr_index = 0;
	DSA *dsa_key = DSA_new();

	if (extract_attr_to_object(TEE_ATTR_DSA_PRIME, params, paramCount, object, i++) &&
	    extract_attr_to_object(TEE_ATTR_DSA_SUBPRIME, params, paramCount, object, i++) &&
	    extract_attr_to_object(TEE_ATTR_DSA_BASE, params, paramCount, object, i++)) {
		DSA_free(dsa_key);
		return -1;
	}

	attr_index = get_attr_index(object, TEE_ATTR_DSA_PRIME);
	BN_bin2bn(object->attrs[attr_index].content.ref.buffer, object->attrs[attr_index].content.ref.length, dsa_key->p);
	attr_index = get_attr_index(object, TEE_ATTR_DSA_SUBPRIME);
	BN_bin2bn(object->attrs[attr_index].content.ref.buffer, object->attrs[attr_index].content.ref.length, dsa_key->q);
	attr_index = get_attr_index(object, TEE_ATTR_DSA_BASE);
	BN_bin2bn(object->attrs[attr_index].content.ref.buffer, object->attrs[attr_index].content.ref.length, dsa_key->g);

	if (!DSA_generate_key(dsa_key)) {
		DSA_free(dsa_key);
		return 0;
	}

	if (bn2ref_to_obj(dsa_key->pub_key, TEE_ATTR_DSA_PUBLIC_VALUE, object, i++) == -1 ||
	    bn2ref_to_obj(dsa_key->priv_key, TEE_ATTR_DSA_PRIVATE_VALUE, object, i++) == -1) {
		DSA_free(dsa_key);
		return -1;
	}

	DSA_free(dsa_key);

	return 1;
}

static int gen_dh_keypair(TEE_ObjectHandle object, TEE_Attribute* params, uint32_t paramCount)
{
	int i = 0, attr_index = 0;
	DH *dh_key = DH_new();

	if (extract_attr_to_object(TEE_ATTR_DH_PRIME, params, paramCount, object, i++) &&
	    extract_attr_to_object(TEE_ATTR_DH_BASE, params, paramCount, object, i++)) {
		DH_free(dh_key);
		return -1;
	}

	attr_index = get_attr_index(object, TEE_ATTR_DH_PRIME);
	BN_bin2bn(object->attrs[attr_index].content.ref.buffer, object->attrs[attr_index].content.ref.length, dh_key->p);
	attr_index = get_attr_index(object, TEE_ATTR_DH_BASE);
	BN_bin2bn(object->attrs[attr_index].content.ref.buffer, object->attrs[attr_index].content.ref.length, dh_key->g);

	if (!DH_generate_key(dh_key))
		return -1;

	if (bn2ref_to_obj(dh_key->pub_key, TEE_ATTR_DH_PUBLIC_VALUE, object, i++) == -1 ||
	    bn2ref_to_obj(dh_key->priv_key, TEE_ATTR_DH_PRIVATE_VALUE, object, i++) == -1) {
		DH_free(dh_key);
		return -1;
	}

	DH_free(dh_key);

	return 1;
}

static bool is_value_attribute(uint32_t attr_ID)
{
	/* Bit [29]:
	 * 0: buffer attribute
	 * 1: value attribute
	 */
	return (attr_ID & TEE_ATTR_FLAG_VALUE);
}

static bool multiple_of_8(uint32_t number)
{
	return !(number % 8) ? true : false;
}

static bool multiple_of_64(uint32_t number)
{
	return !(number % 64) ? true : false;
}

static void reset_attrs(TEE_ObjectHandle obj)
{
	size_t i;

	for (i = 0; i < obj->attrs_count; ++i) {
		if (!is_value_attribute(obj->attrs[i].attributeID)) {
			memset(obj->attrs[i].content.ref.buffer, 0, obj->attrs[i].content.ref.length);
		}

		memset(&obj->attrs[i], 0, sizeof(TEE_Attribute));
	}
}

static bool malloc_for_attrs(TEE_ObjectHandle object, uint32_t attrs_count)
{
	size_t i;

	for (i = 0; i < attrs_count; ++i) {
		object->attrs[i].content.ref.buffer = NULL;
		object->attrs[i].content.ref.buffer = TEE_Malloc(object->maxObjSizeBytes, 0);
		if (object->attrs[i].content.ref.buffer == NULL)
			return false;

		object->attrs[i].content.ref.length = object->maxObjSizeBytes; /* malloc space (or should be maxObjectSize?) */
	}

	return true;
}

static void free_attrs(TEE_ObjectHandle object)
{
	size_t i;

	for (i = 0; i < object->attrs_count; ++i) {
		if (!is_value_attribute(object->attrs[i].attributeID)) {
			memset(object->attrs[i].content.ref.buffer, 0, object->attrs[i].content.ref.length);
			free(object->attrs[i].content.ref.buffer);
		}
		memset(&object->attrs[i], 0, sizeof(TEE_Attribute));
	}

}

static bool valid_object_max_size(object_type obj, uint32_t size)
{
	switch (obj) {
	case TEE_TYPE_AES:
		if (size == 128 || size == 192 || size == 256)
			return true;
		return false;

	case TEE_TYPE_DES:
		if (size == 56)
			return true;
		return false;

	case TEE_TYPE_DES3:
		if (size == 112 || size == 168)
			return true;
		return false;

	case TEE_TYPE_HMAC_MD5:
		if (size >= 80 && size <= 512 && multiple_of_8(size))
			return true;
		return false;

	case TEE_TYPE_HMAC_SHA1:
		if (size >= 112 && size <= 512 && multiple_of_8(size))
			return true;
		return false;

	case TEE_TYPE_HMAC_SHA224:
		if (size >= 192 && size <= 512 && multiple_of_8(size))
			return true;
		return false;

	case TEE_TYPE_HMAC_SHA256:
		if (size >= 256 && size <= 1024 && multiple_of_8(size))
			return true;
		return false;

	case TEE_TYPE_HMAC_SHA384:
		if (size >= 64 && size <= 1024 && multiple_of_8(size))
			return true;
		return false;

	case TEE_TYPE_HMAC_SHA512:
		if (size >= 64 && size <= 1024 && multiple_of_8(size))
			return true;
		return false;

	case TEE_TYPE_RSA_PUBLIC_KEY:
		if (size >= 256 && size <= 2048)
			return true;
		return false;

	case TEE_TYPE_RSA_KEYPAIR:
		if (size >= 256 && size <= 2048)
			return true;
		return false;

	case TEE_TYPE_DSA_PUBLIC_KEY:
		if (size >= 512 && size <= 1024 && multiple_of_64(size))
			return true;
		return false;

	case TEE_TYPE_DSA_KEYPAIR:
		if (size >= 512 && size <= 1024 && multiple_of_64(size))
			return true;
		return false;

	case TEE_TYPE_DH_KEYPAIR:
		if (size >= 256 && size <= 2048)
			return true;
		return false;

	case TEE_TYPE_GENERIC_SECRET:
		if (size >= 8 && size <= 4096 && multiple_of_8(size))
			return true;
		return false;

	default:
		return false;
	}
}

static int valid_obj_type_and_attr_count(object_type obj)
{
	switch (obj) {
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
		return 1;

	case TEE_TYPE_RSA_PUBLIC_KEY:
		return 2;

	case TEE_TYPE_RSA_KEYPAIR:
		return 8;

	case TEE_TYPE_DSA_PUBLIC_KEY:
		return 4;

	case TEE_TYPE_DSA_KEYPAIR:
		return 5;

	case TEE_TYPE_DH_KEYPAIR:
		return 5;

	default:
		return -1;
	}
}

static int get_attr_index(TEE_ObjectHandle object, uint32_t attributeID)
{
	size_t i;

	for (i = 0; i < object->attrs_count; ++i) {
		if (object->attrs[i].attributeID == attributeID)
			return i;
	}

	return -1;
}


/*
 * ## Internal API functions ##
 */

void TEE_GetObjectInfo(TEE_ObjectHandle object, TEE_ObjectInfo* objectInfo)
{
	if (object == NULL || objectInfo == NULL)
		return;

	memcpy(objectInfo, &object->objectInfo, sizeof(objectInfo));
}

void TEE_RestrictObjectUsage(TEE_ObjectHandle object, uint32_t objectUsage)
{
	if (object == NULL)
		return;

	object->objectInfo.objectUsage ^= objectUsage;
}

TEE_Result TEE_GetObjectBufferAttribute(TEE_ObjectHandle object, uint32_t attributeID, void* buffer, size_t* size)
{
	int attr_index = -1;

	/* Check input parameters */
	if (object == NULL) {
		syslog(LOG_ERR, "Object NULL\n");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	if (buffer == NULL) {
		syslog(LOG_ERR, "buffer NULL\n");
		return TEE_ERROR_SHORT_BUFFER;
	}

	/* Is this buffer attribute */
	if (is_value_attribute(attributeID)) {
		/* panic(); */
		syslog(LOG_ERR, "Not a buffer attribute\n");
		return TEE_ERROR_GENERIC;
	}

	/* Find attribute, if it is found */
	attr_index = get_attr_index(object, attributeID);

	/* NB! This take a count initialization status! */
	if (attr_index == -1) {
		syslog(LOG_ERR, "Attribute not found\n");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	/* Attribute found*/

	if (!(attributeID & TEE_ATTR_FLAG_PUBLIC) && !(object->objectInfo.objectUsage ^ TEE_USAGE_EXTRACTABLE)) {
		/* panic(); */
		syslog(LOG_ERR, "Not axtractable attribute\n");
		return TEE_ERROR_GENERIC;
	}

	if (object->attrs[attr_index].content.ref.length > *size) {
		syslog(LOG_ERR, "Short buffer\n");
		return TEE_ERROR_SHORT_BUFFER;
	}

	memcpy(buffer, &object->attrs[attr_index].content.ref.buffer, object->attrs[attr_index].content.ref.length);
	*size = object->attrs[attr_index].content.ref.length;

	return TEE_SUCCESS;
}

TEE_Result TEE_GetObjectValueAttribute(TEE_ObjectHandle object, uint32_t attributeID, uint32_t* a, uint32_t* b)
{
	int attr_index = -1;

	/* Check input parameters */
	if (object == NULL) {
		syslog(LOG_ERR, "Object NULL\n");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	if (a == NULL && b == NULL) {
		syslog(LOG_ERR, "A and B NULL\n");
		return TEE_SUCCESS; /* ? */
	}

	if (!is_value_attribute(attributeID)) {
		/* panic(); */
	}

	/* Find attribute, if it is found */

	attr_index = get_attr_index(object, attributeID);

	/* NB! This take a count initialization status! */
	if (attr_index == -1) {
		syslog(LOG_ERR, "Attribute not found\n");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	/* Attribute found */

	if (!(attributeID & TEE_ATTR_FLAG_PUBLIC) && !(object->objectInfo.objectUsage ^ TEE_USAGE_EXTRACTABLE)) {
		/* panic(); */
		syslog(LOG_ERR, "Not axtractable attribute\n");
		return TEE_ERROR_GENERIC;
	}

	if (a != NULL)
		*a = object->attrs[attr_index].content.value.a;

	if (b != NULL)
		*b = object->attrs[attr_index].content.value.b;

	return TEE_SUCCESS;
}

void TEE_CloseObject(TEE_ObjectHandle object)
{
	if (object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) {
		release_file(object->per_obj_id, object->per_obj_id_len);
		fclose(object->per_obj_file_handler);
		free_attrs(object);
		free(object->attrs);
		memset(object, 0, sizeof(TEE_ObjectHandle));
		free(object);
		return;
	}

	TEE_FreeTransientObject(object);
}

TEE_Result TEE_AllocateTransientObject(uint32_t objectType, uint32_t maxObjectSize, TEE_ObjectHandle* object)
{
	TEE_ObjectHandle tmp_handle;
	int attr_count = valid_obj_type_and_attr_count(objectType);

	/* Check parameters */
	if (attr_count == -1) {
		syslog(LOG_ERR, "Not valid object type\n");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (!valid_object_max_size(objectType, maxObjectSize)) {
		syslog(LOG_ERR, "Not valid object max size\n");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	/* Alloc memory for objectHandle */
	tmp_handle = TEE_Malloc(sizeof(struct __TEE_ObjectHandle), 0);
	if (tmp_handle == NULL)
		goto out_of_mem_handle;

	/* object info */
	tmp_handle->objectInfo.objectUsage = 0xFFFFFFFF;
	tmp_handle->objectInfo.maxObjectSize = maxObjectSize;
	tmp_handle->objectInfo.objectType = objectType;
	tmp_handle->objectInfo.objectSize = 0;
	tmp_handle->objectInfo.dataSize = 0;
	tmp_handle->objectInfo.handleFlags = 0x00000000;
	tmp_handle->attrs_count = attr_count;
	tmp_handle->maxObjSizeBytes = (maxObjectSize + 7) / 8;

	/* Alloc memory for attributes (pointers) */
	tmp_handle->attrs = TEE_Malloc(attr_count * sizeof(TEE_Attribute), 0);
	if (tmp_handle->attrs == NULL)
		goto out_of_mem_attrs_ptr;

	/* Alloc memory for object attributes */
	switch(objectType) {
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
	case TEE_TYPE_RSA_KEYPAIR:
	case TEE_TYPE_DSA_PUBLIC_KEY:
	case TEE_TYPE_DSA_KEYPAIR:
		if (!malloc_for_attrs(tmp_handle, attr_count))
			goto out_of_mem_attrs;
		break;

	case TEE_TYPE_DH_KEYPAIR:
		/* -1, because DH contains one value attribute */
		if (!malloc_for_attrs(tmp_handle, attr_count-1))
			goto out_of_mem_attrs;
		break;

	default:
		/* Should never get here
		 * Let's free all memory */
		goto out_of_mem_attrs_ptr;
		break;
	}

	*object = tmp_handle;

	return TEE_SUCCESS;

out_of_mem_attrs:
	free(tmp_handle->attrs);
out_of_mem_attrs_ptr:
	free(tmp_handle);
out_of_mem_handle:
	syslog(LOG_ERR, "Out of memory\n");

	return TEE_ERROR_OUT_OF_MEMORY;
}

void TEE_FreeTransientObject(TEE_ObjectHandle object)
{
	if (object == NULL || object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)
		return;

	free_attrs(object);
	free(object->attrs);
	memset(object, 0, sizeof(TEE_ObjectHandle));
	free(object);
}

void TEE_ResetTransientObject(TEE_ObjectHandle object)
{
	if (object == NULL || object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)
		return;

	/* Reset info */
	object->objectInfo.objectUsage = 0xFFFFFFFF;
	object->objectInfo.objectSize = 0;
	object->objectInfo.dataSize = 0;
	object->objectInfo.handleFlags = 0x00000000;

	reset_attrs(object);
}

TEE_Result TEE_PopulateTransientObject(TEE_ObjectHandle object, TEE_Attribute* attrs, uint32_t attrCount)
{
	uint32_t i = 0;

	if (object == NULL || attrs == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if (object->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) {
		syslog(LOG_ERR, "Can not populate initialized object\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	switch(object->objectInfo.objectType) {
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
		if (extract_attr_to_object(TEE_ATTR_SECRET_VALUE, attrs, attrCount, object, i++))
			break;

	case TEE_TYPE_RSA_PUBLIC_KEY:
		if (extract_attr_to_object(TEE_ATTR_RSA_MODULUS, attrs, attrCount, object, i++) &&
		    extract_attr_to_object(TEE_ATTR_RSA_PUBLIC_EXPONENT, attrs, attrCount, object, i++))
			break;

	case TEE_TYPE_RSA_KEYPAIR:
		if (does_arr_contain_attrID(TEE_ATTR_RSA_PRIME1, attrs, attrCount) ||
		    does_arr_contain_attrID(TEE_ATTR_RSA_PRIME2, attrs, attrCount) ||
		    does_arr_contain_attrID(TEE_ATTR_RSA_EXPONENT1, attrs, attrCount) ||
		    does_arr_contain_attrID(TEE_ATTR_RSA_EXPONENT2, attrs, attrCount) ||
		    does_arr_contain_attrID(TEE_ATTR_RSA_COEFFICIENT, attrs, attrCount)) {

			if (extract_attr_to_object(TEE_ATTR_RSA_MODULUS, attrs, attrCount, object, i++) &&
			    extract_attr_to_object(TEE_ATTR_RSA_PUBLIC_EXPONENT, attrs, attrCount, object, i++) &&
			    extract_attr_to_object(TEE_ATTR_RSA_PRIVATE_EXPONENT, attrs, attrCount, object, i++) &&
			    extract_attr_to_object(TEE_ATTR_RSA_PRIME1, attrs, attrCount, object, i++) &&
			    extract_attr_to_object(TEE_ATTR_RSA_PRIME2, attrs, attrCount, object, i++) &&
			    extract_attr_to_object(TEE_ATTR_RSA_EXPONENT1, attrs, attrCount, object, i++) &&
			    extract_attr_to_object(TEE_ATTR_RSA_EXPONENT2, attrs, attrCount, object, i++) &&
			    extract_attr_to_object(TEE_ATTR_RSA_COEFFICIENT, attrs, attrCount, object, i++))
				break;
		}

		else {
			if (extract_attr_to_object(TEE_ATTR_RSA_MODULUS, attrs, attrCount, object, i++) &&
			    extract_attr_to_object(TEE_ATTR_RSA_PUBLIC_EXPONENT, attrs, attrCount, object, i++) &&
			    extract_attr_to_object(TEE_ATTR_RSA_PRIVATE_EXPONENT, attrs, attrCount, object, i++))
				break;
		}

	case TEE_TYPE_DSA_PUBLIC_KEY:
		if (extract_attr_to_object(TEE_ATTR_DSA_PRIME, attrs, attrCount, object, i++) &&
		    extract_attr_to_object(TEE_ATTR_DSA_SUBPRIME, attrs, attrCount, object, i++) &&
		    extract_attr_to_object(TEE_ATTR_DSA_BASE, attrs, attrCount, object, i++) &&
		    extract_attr_to_object(TEE_ATTR_DSA_PUBLIC_VALUE, attrs, attrCount, object, i++))
			break;

	case TEE_TYPE_DSA_KEYPAIR:
		if (extract_attr_to_object(TEE_ATTR_DSA_PRIME, attrs, attrCount, object, i++) &&
		    extract_attr_to_object(TEE_ATTR_DSA_SUBPRIME, attrs, attrCount, object, i++) &&
		    extract_attr_to_object(TEE_ATTR_DSA_BASE, attrs, attrCount, object, i++) &&
		    extract_attr_to_object(TEE_ATTR_DSA_PRIVATE_VALUE, attrs, attrCount, object, i++) &&
		    extract_attr_to_object(TEE_ATTR_DSA_PUBLIC_VALUE, attrs, attrCount, object, i++))
			break;

	case TEE_TYPE_DH_KEYPAIR:
		if (extract_attr_to_object(TEE_ATTR_DH_PRIME, attrs, attrCount, object, i++) &&
		    extract_attr_to_object(TEE_ATTR_DH_BASE, attrs, attrCount, object, i++) &&
		    extract_attr_to_object(TEE_ATTR_DH_PUBLIC_VALUE, attrs, attrCount, object, i++) &&
		    extract_attr_to_object(TEE_ATTR_DH_PRIVATE_VALUE, attrs, attrCount, object, i++)) {
			extract_attr_to_object(TEE_ATTR_DH_SUBPRIME, attrs, attrCount, object, i++);
			break;
		}

	default:
		/* Correct response would be PANIC, but not yet implmented */
		free_attrs(object);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	object->objectInfo.handleFlags |= TEE_HANDLE_FLAG_INITIALIZED; /* TODO: CHECK!! */
	
	return TEE_SUCCESS;
}

void TEE_InitRefAttribute(TEE_Attribute* attr, uint32_t attributeID, void* buffer, size_t length)
{
	if (attr == NULL)
		return;
	
	if (is_value_attribute(attributeID)) {
		syslog(LOG_ERR, "Not a value attribute\n");
		/* panic() */
	}

	attr->content.ref.buffer = buffer;
	attr->content.ref.length = length;
}

void TEE_InitValueAttribute(TEE_Attribute* attr, uint32_t attributeID, uint32_t a, uint32_t b)
{
	if (attr == NULL)
		return;

	if (!is_value_attribute(attributeID)) {
		syslog(LOG_ERR, "Not a value attribute\n");
		/* panic() */
	}

	attr->content.value.a = a;
	attr->content.value.b = b;
}

void TEE_CopyObjectAttributes(TEE_ObjectHandle destObject, TEE_ObjectHandle srcObject)
{
	size_t i = 0;

	if (destObject == NULL || srcObject == NULL)
		return;

	if (destObject->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED ||
	    !(srcObject->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED)) {
		/* Correct would e panic, but not implemented (yet) */
		return;
	}

	if (srcObject->maxObjSizeBytes > destObject->maxObjSizeBytes) {
		/* Correct would e panic, but not implemented (yet) */
		return;
	}

	/* Extract attributes, if possible */
	if (destObject->objectInfo.objectType == srcObject->objectInfo.objectType) {
		if (srcObject->attrs_count != destObject->attrs_count) {
			syslog(LOG_ERR, "Can not copy objects, because attribute count do not match\n");
			return;
		}

		if (copy_obj_attr_to_obj(srcObject, EMU_ALL, destObject, 0) < 0) {
			syslog(LOG_ERR, "Can not copy objects, because something went wrong\n");
			return;
		}
	}

	else if (destObject->objectInfo.objectType == TEE_TYPE_RSA_PUBLIC_KEY &&
		 srcObject->objectInfo.objectType == TEE_TYPE_RSA_KEYPAIR) {
		if (copy_obj_attr_to_obj(srcObject, TEE_ATTR_RSA_MODULUS, destObject, i++) < 0 ||
		    copy_obj_attr_to_obj(srcObject, TEE_ATTR_RSA_PUBLIC_EXPONENT, destObject, i++) < 0) {
			syslog(LOG_ERR, "Can not copy objects, because something went wrong\n");
			return;
		}

	}

	else if (destObject->objectInfo.objectType == TEE_TYPE_DSA_PUBLIC_KEY &&
		 srcObject->objectInfo.objectType == TEE_TYPE_DSA_KEYPAIR) {
		if (copy_obj_attr_to_obj(srcObject, TEE_ATTR_DSA_PUBLIC_VALUE, destObject, i++) < 0 ||
		    copy_obj_attr_to_obj(srcObject, TEE_ATTR_DSA_SUBPRIME, destObject, i++) < 0 ||
		    copy_obj_attr_to_obj(srcObject, TEE_ATTR_DSA_BASE, destObject, i++) < 0 ||
		    copy_obj_attr_to_obj(srcObject, TEE_ATTR_DSA_PRIME, destObject, i++) < 0) {
			syslog(LOG_ERR, "Can not copy objects, because something went wrong\n");
			return;
		}
	}

	else {
		/* Correct would e panic, but not implemented (yet) */
		return;
	}

	destObject->objectInfo.handleFlags |= TEE_HANDLE_FLAG_INITIALIZED;
}

TEE_Result TEE_GenerateKey(TEE_ObjectHandle object, uint32_t keySize, TEE_Attribute* params, uint32_t paramCount)
{
	int ret_val = -1;

	if (object == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if (object->objectInfo.maxObjectSize < keySize) {
		syslog(LOG_ERR, "KeySize is too large\n");
		/* panic() */
		return TEE_ERROR_GENERIC;
	}

	/* Should be a transient object and uninit */
	if (object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT ||
	    object->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) {
		/* panic() */
		return TEE_ERROR_GENERIC;
	}

	switch(object->objectInfo.objectType) {
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
		ret_val = gen_10_key(object, keySize);
		break;

	case TEE_TYPE_RSA_KEYPAIR:
		ret_val = gen_rsa_keypair(object, keySize);
		break;

	case TEE_TYPE_DSA_KEYPAIR:
		ret_val = gen_dsa_keypair(object, params, paramCount);
		break;

	case TEE_TYPE_DH_KEYPAIR:
		ret_val = gen_dh_keypair(object, params, paramCount);
		break;

	default:
		break; /* panic() Should never get here */
	}

	openssl_cleanup();

	if (ret_val == -1) {
		/* If ret_val is -1, KeySize too large or mandatory parameter missing
		 * Correct response would be PANIC, but not yet implmented */
		return TEE_ERROR_GENERIC;
	}

	if (ret_val == 0) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	object->objectInfo.handleFlags |= TEE_HANDLE_FLAG_INITIALIZED;

	return TEE_SUCCESS;
}

TEE_Result TEE_OpenPersistentObject(uint32_t storageID, void* objectID, size_t objectIDLen, uint32_t flags, TEE_ObjectHandle* object)
{
	TEE_ObjectHandle tmp_handle;
	struct persistant_object tmp_persistant_object;
	FILE* tmp_per_obj_file;
	TEE_Result ret_val;
	long data_begin;
	long data_size;

	if (object == NULL)
		return TEE_ERROR_GENERIC;

	if (storageID != TEE_STORAGE_PRIVATE)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (objectID == NULL) {
		syslog(LOG_ERR, "ObjectID buffer is NULL\n");
		return TEE_ERROR_GENERIC;
	}

	if (objectIDLen > TEE_OBJECT_ID_MAX_LEN) {
		return TEE_ERROR_GENERIC; /* replace to panic(), when implemented */
	}

	tmp_per_obj_file = query_for_access(objectID, objectIDLen, flags);
	if (tmp_per_obj_file == NULL) {
		/* This should also check, if objID exists */
		syslog(LOG_ERR, "Access conflict\n");
		return TEE_ERROR_ACCESS_CONFLICT;
	}

	tmp_handle = TEE_Malloc(sizeof(struct __TEE_ObjectHandle), 0);
	if (tmp_handle == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	tmp_handle->per_obj_file_handler = tmp_per_obj_file;

	memset(&tmp_persistant_object, 0, sizeof(struct persistant_object));
	if (fread(&tmp_persistant_object, sizeof(struct persistant_object), 1, tmp_handle->per_obj_file_handler) != 1)
		goto err_at_meta_read;

	memcpy(&tmp_handle->objectInfo, &tmp_persistant_object.info, sizeof(struct persistant_object));
	tmp_handle->attrs_count = tmp_persistant_object.attrs_count;
	
	if (tmp_handle->attrs_count > 0) {
		tmp_handle->maxObjSizeBytes = (tmp_persistant_object.info.maxObjectSize + 7) / 8;
		ret_val = load_attributes(tmp_handle);
		if (ret_val == TEE_ERROR_OUT_OF_MEMORY || ret_val == TEE_ERROR_GENERIC) {
			free(tmp_handle);
			return ret_val;
		}
	}

	data_begin = ftell(tmp_handle->per_obj_file_handler);
	fseek(tmp_handle->per_obj_file_handler, 0, SEEK_END);
	data_size = ftell(tmp_handle->per_obj_file_handler) - data_begin;
	fseek(tmp_handle->per_obj_file_handler, data_begin, SEEK_SET);

	if (data_size >= UINT32_MAX) {
		syslog(LOG_ERR, "Data size too large\n");
		return TEE_ERROR_GENERIC;
	}

	tmp_handle->objectInfo.dataSize = data_size;
	tmp_handle->objectInfo.dataPosition = data_begin;
	tmp_handle->data_begin = data_begin;

	memcpy(tmp_handle->per_obj_id, objectID, objectIDLen);
	tmp_handle->per_obj_id_len = objectIDLen;

	tmp_handle->objectInfo.handleFlags |= (TEE_HANDLE_FLAG_PERSISTENT | TEE_HANDLE_FLAG_INITIALIZED);
	*object = tmp_handle;

	return TEE_SUCCESS;

err_at_meta_read:
	free(tmp_handle);
	return TEE_ERROR_GENERIC;
}

TEE_Result TEE_CreatePersistentObject(uint32_t storageID, void* objectID, size_t objectIDLen, uint32_t flags, TEE_ObjectHandle attributes, void* initialData, size_t initialDataLen, TEE_ObjectHandle* object)
{
	struct persistant_object tmp_per_obj;
	size_t i;
	FILE* tmp_per_obj_file;
	TEE_Result ret_val;

	if (storageID != TEE_STORAGE_PRIVATE)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (objectID == NULL) {
		syslog(LOG_ERR, "ObjectID buffer is NULL\n");
		return TEE_ERROR_GENERIC;
	}

	if (objectIDLen > TEE_OBJECT_ID_MAX_LEN) {
		return TEE_ERROR_GENERIC; /* replace to panic(), when implemented */
	}

	if (attributes != NULL && !(attributes->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED)) {
		return TEE_ERROR_GENERIC; /* replace to panic(), when implemented */
	}

	tmp_per_obj_file = query_for_access(objectID, objectIDLen, flags);
	if (tmp_per_obj_file == NULL) {
		syslog(LOG_ERR, "Access conflict\n");
		return TEE_ERROR_ACCESS_CONFLICT;
	}

	memset(&tmp_per_obj, 0, sizeof(struct persistant_object));
	if (attributes != NULL) {
		memcpy(&tmp_per_obj.info, &attributes->objectInfo, sizeof(TEE_ObjectInfo));
		tmp_per_obj.attrs_count = attributes->attrs_count;
	}
	else {
		tmp_per_obj.attrs_count = 0;
	}

	memcpy(tmp_per_obj.per_obj_id, objectID, objectIDLen);
	tmp_per_obj.obj_id_len = objectIDLen;

	if (fwrite(&tmp_per_obj, sizeof(struct persistant_object), 1, tmp_per_obj_file) != 1)
		goto err_at_meta_data_write;

	if (attributes != NULL && attributes->attrs_count > 0) {
		for (i = 0; i < attributes->attrs_count; ++i) {
			if (fwrite(&attributes->attrs[i], sizeof(TEE_Attribute), 1, tmp_per_obj_file) != 1)
				goto err_at_meta_data_write;

			if (!is_value_attribute(attributes->attrs[i].attributeID))
				if (fwrite(attributes->attrs[i].content.ref.buffer, attributes->attrs[i].content.ref.length, 1, tmp_per_obj_file) != 1)
					goto err_at_meta_data_write;
		}
	}

	if (initialData != NULL) {
		fwrite(initialData, initialDataLen, 1, tmp_per_obj_file);
	}

	fflush(tmp_per_obj_file);

	if (object != NULL) {
		*object = TEE_Malloc(sizeof(struct __TEE_ObjectHandle), 0);
		if (*object == NULL)
			return TEE_ERROR_OUT_OF_MEMORY;

		memcpy(attributes, *object, sizeof(struct __TEE_ObjectHandle));
		(*object)->per_obj_file_handler = tmp_per_obj_file;

		if ((*object)->attrs_count > 0) {
			ret_val = load_attributes((*object));
			if (ret_val == TEE_ERROR_OUT_OF_MEMORY || ret_val == TEE_ERROR_GENERIC) {
				free((*object));
				return ret_val;
			}
		}

		(*object)->objectInfo.handleFlags |= (TEE_HANDLE_FLAG_PERSISTENT | TEE_HANDLE_FLAG_INITIALIZED);
		(*object)->data_begin = ftell((*object)->per_obj_file_handler);
		(*object)->objectInfo.dataSize = initialDataLen;
		if ((*object)->data_begin >= UINT32_MAX) {
			syslog(LOG_ERR, "Data size too large\n");
			TEE_CloseAndDeletePersistentObject((*object));
			return TEE_ERROR_GENERIC;
		}
		(*object)->objectInfo.dataPosition = (*object)->data_begin;
		memcpy((*object)->per_obj_id, objectID, objectIDLen);
		(*object)->per_obj_id_len = objectIDLen;

	}
	else {
		release_file(objectID, objectIDLen);
		fclose(tmp_per_obj_file); /* Replace with NULL in future */
	}

	return TEE_SUCCESS;

err_at_meta_data_write:
	delete_file(objectID, objectIDLen);
	syslog(LOG_ERR, "Error with write\n");
	return TEE_ERROR_GENERIC;
}

TEE_Result TEE_RenamePersistentObject(TEE_ObjectHandle object, void* newObjectID, size_t newObjectIDLen)
{
	FILE *tmp;

	if (object == NULL || !(object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)) {
		syslog(LOG_ERR, "ObjectID buffer is NULL or not persistant object\n");
		return TEE_ERROR_GENERIC; /* replace to panic(), when implemented */
	}

	if (newObjectIDLen > TEE_OBJECT_ID_MAX_LEN) {
		return TEE_ERROR_GENERIC; /* replace to panic(), when implemented */
	}

	if (!(object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_WRITE_META) || object->per_obj_file_handler == NULL) {
		syslog(LOG_ERR, "TEE_RenamePerObj: No rights or not valid object\n");
		return TEE_ERROR_GENERIC; /* replace to panic(), when implemented */
	}

	tmp = is_object_id_in_use(object, newObjectID, newObjectIDLen);
	if (tmp == NULL) {
		syslog(LOG_ERR, "Access conflict: ID exists\n");
		return TEE_ERROR_ACCESS_CONFLICT;
	}

	object->per_obj_file_handler = tmp;
	fseek(object->per_obj_file_handler, object->data_begin, SEEK_SET);
	memcpy(object->per_obj_id, newObjectID, newObjectIDLen);
	object->per_obj_id_len = newObjectIDLen;

	return TEE_SUCCESS;
}

void TEE_CloseAndDeletePersistentObject(TEE_ObjectHandle object)
{
	if (object == NULL || !(object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)) {
		syslog(LOG_ERR, "ObjectID buffer is NULL or not persistant object\n");
		return; /* replace to panic(), when implemented */
	}

	if (!(object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_WRITE_META) || object->per_obj_file_handler == NULL) {
		syslog(LOG_ERR, "TEE_RenamePerObj: No rights or not valid object\n");
		return; /* replace to panic(), when implemented */
	}

	delete_file(object->per_obj_id, object->per_obj_id_len);
	fclose(object->per_obj_file_handler); /*replace with NULL*/
	free_attrs(object);
	free(object->attrs);
	free(object);
}

TEE_Result TEE_AllocatePersistentObjectEnumerator(TEE_ObjectEnumHandle* objectEnumerator)
{
	if (objectEnumerator == NULL)
		return TEE_ERROR_GENERIC;

	*objectEnumerator = TEE_Malloc(sizeof(struct __TEE_ObjectEnumHandle), 0);
	if (*objectEnumerator == NULL) {
		*objectEnumerator = NULL;
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	return TEE_SUCCESS;
}

void TEE_FreePersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator)
{
	if (objectEnumerator == NULL)
		return;

	closedir(objectEnumerator->dir);
	free(objectEnumerator);
}

void TEE_ResetPersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator)
{
	if (objectEnumerator == NULL)
		return;

	closedir(objectEnumerator->dir);
	memset(objectEnumerator, 0, sizeof(struct __TEE_ObjectEnumHandle));
}

TEE_Result TEE_StartPersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator, uint32_t storageID)
{
	char *dir_path = NULL;
	char UUID[sizeof(TEE_UUID)];

	if (storageID != TEE_STORAGE_PRIVATE)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (objectEnumerator == NULL)
		return TEE_ERROR_GENERIC;

	get_uuid(UUID);

	if (asprintf(&dir_path, "%s%s/", SECURE_STORAGE_PATH, UUID) == -1) {
		return TEE_ERROR_GENERIC; // TEE_ERROR_OUT_OF_MEMORY;
	}

	objectEnumerator->dir = opendir(dir_path);
	free(dir_path);

	return TEE_SUCCESS;
}

TEE_Result TEE_GetNextPersistentObject(TEE_ObjectEnumHandle objectEnumerator, TEE_ObjectInfo objectInfo, void* objectID, size_t* objectIDLen)
{
	struct persistant_object per_obj;
	struct dirent *entry;
	char *name_with_path = NULL;
	FILE *tmp_file;
	char UUID[sizeof(TEE_UUID)];

	get_uuid(UUID);

	if (objectEnumerator == NULL || objectID == NULL || objectIDLen == NULL)
		return TEE_ERROR_GENERIC;

	if (objectEnumerator->dir == NULL) {
		syslog(LOG_ERR, "Enumeration is not started\n");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

next_file:

	while ((entry = readdir(objectEnumerator->dir)) != NULL) {
		if (entry->d_name[0] == '.')
			continue;
	}

	if (entry == NULL) {
		syslog(LOG_DEBUG, "Enumeration has reached end\n");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	if (asprintf(&name_with_path, "%s%s/%s", SECURE_STORAGE_PATH, UUID, entry->d_name) == -1) {
		return TEE_ERROR_GENERIC; // TEE_ERROR_OUT_OF_MEMORY;
	}

	tmp_file = fopen(name_with_path, "rb");
	if (tmp_file == NULL) {
		syslog(LOG_ERR, "Cannot peek into file (enumeration)\n");
		goto next_file;
	}

	free(name_with_path);

	if (fread(&per_obj, 1, sizeof(struct persistant_object), tmp_file) != 1) {
		syslog(LOG_ERR, "Cannot read file (enumeration)\n");
		fclose(tmp_file);
		return TEE_ERROR_GENERIC;
	}

	fclose(tmp_file);

	memcpy(&objectInfo, &per_obj.info, sizeof(TEE_ObjectInfo));
	if (per_obj.obj_id_len > *objectIDLen)
		return TEE_ERROR_GENERIC;

	memcpy(objectID, per_obj.per_obj_id, per_obj.obj_id_len);
	*objectIDLen = per_obj.obj_id_len;

	return TEE_SUCCESS;
}

TEE_Result TEE_ReadObjectData(TEE_ObjectHandle object, void* buffer, size_t size, uint32_t* count)
{
	if (object == NULL || object->per_obj_file_handler == NULL)
		return TEE_ERROR_GENERIC;

	if (!(object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_READ)) {
		syslog(LOG_ERR, "Can not read persistant object data: Not proper access rights\n");
		return TEE_ERROR_GENERIC; /* replace to panic(), when implemented */
	}

	*count = fread(buffer, 1, size, object->per_obj_file_handler);

	object->objectInfo.dataPosition += *count;

	return TEE_SUCCESS;
}

TEE_Result TEE_WriteObjectData(TEE_ObjectHandle object, void* buffer, size_t size)
{
	size_t write_bytes;

	if (object == NULL || object->per_obj_file_handler == NULL)
		return TEE_ERROR_GENERIC;

	if (!(object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_WRITE)) {
		syslog(LOG_ERR, "Can not write persistant object data: Not proper access rights\n");
		return TEE_ERROR_GENERIC; /* replace to panic(), when implemented */
	}

	write_bytes = fwrite(buffer, 1, size, object->per_obj_file_handler);

	object->objectInfo.dataPosition += write_bytes;
	object->objectInfo.dataSize += write_bytes;

	return TEE_SUCCESS;
}

TEE_Result TEE_TruncateObjectData(TEE_ObjectHandle object, uint32_t size)
{
	if (object == NULL || object->per_obj_file_handler == NULL)
		return TEE_ERROR_GENERIC;

	if (!(object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_WRITE)) {
		syslog(LOG_ERR, "Can not write persistant object data: Not proper access rights\n");
		return TEE_ERROR_GENERIC; /* replace to panic(), when implemented */
	}

	if (size >= object->data_begin)
		ftruncate(fileno(object->per_obj_file_handler), size);
	else
		ftruncate(fileno(object->per_obj_file_handler), object->data_begin);

	if (size < (object->objectInfo.dataPosition - object->data_begin))
		fseek(object->per_obj_file_handler, size + object->data_begin, SEEK_SET);

	return TEE_SUCCESS;
}

TEE_Result TEE_SeekObjectData(TEE_ObjectHandle object, int32_t offset, TEE_Whence whence)
{
	if (object == NULL || object->per_obj_file_handler == NULL)
		return TEE_ERROR_GENERIC;

	if (whence == TEE_DATA_SEEK_CUR) {
		if (offset < 0) {
			if (abs(offset) > object->objectInfo.dataPosition - object->data_begin) {
				fseek(object->per_obj_file_handler, object->data_begin, SEEK_SET);
				return TEE_SUCCESS;
			}
		}
		else {
			if (offset > object->objectInfo.dataSize - object->data_begin) {
				fseek(object->per_obj_file_handler, object->objectInfo.dataSize + object->data_begin, SEEK_SET);
				return TEE_SUCCESS;
			}
		}
		fseek(object->per_obj_file_handler, offset, SEEK_CUR);
	}
	else if (whence == TEE_DATA_SEEK_END) {
		if (offset > 0) {
			fseek(object->per_obj_file_handler, object->objectInfo.dataSize + object->data_begin, SEEK_END);
			return TEE_SUCCESS;
		}
		else {
			if ((long)offset > object->objectInfo.dataSize) {
				fseek(object->per_obj_file_handler, object->data_begin, SEEK_SET);
				return TEE_SUCCESS;
			}
		}
		fseek(object->per_obj_file_handler, offset, SEEK_END);
	}
	else if (whence == TEE_DATA_SEEK_SET) {
		if (offset < 0) {
			fseek(object->per_obj_file_handler, object->data_begin, SEEK_SET);
			return TEE_SUCCESS;
		}
		else {
			if ((long)offset > object->objectInfo.dataSize) {
				fseek(object->per_obj_file_handler, object->objectInfo.dataSize + object->data_begin, SEEK_SET);
				return TEE_SUCCESS;
			}
		}
		fseek(object->per_obj_file_handler, object->data_begin + offset, SEEK_SET);
	}
	else {
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}













