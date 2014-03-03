 /***************************************************************************
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

#include <sqlite3.h>

#include <stdio.h>
#include <syslog.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "storage_data_key_api.h"
#include "tee_memory.h"

struct __TEE_ObjectHandle {
	TEE_ObjectInfo objectInfo;
	TEE_Attribute *attrs;
	uint32_t attrs_count;
	uint32_t maxObjSizeBytes;
	char per_obj_id[TEE_OBJECT_ID_MAX_LEN + 1];
	size_t per_obj_id_len;
};

#ifndef DB_PATH
#define DB_PATH "/home/dettenbo/TEE_secure_storage/"
#endif
static const uint32_t EMU_ALL = 0xF000001F;
static char UUID_test[] = "56c5d1b260704de30fe7"; /* For testing */


/*
 * ## TEMP ##
 */
static bool multiple_of_8(uint32_t number); /* ok */
static bool multiple_of_64(uint32_t number); /* ok */
static bool is_value_attribute(uint32_t attr_ID); /* ok */
static void reset_attrs(TEE_ObjectHandle obj); /* ok */
static void free_attrs(TEE_ObjectHandle object); /* ok */
static bool malloc_for_attrs(TEE_ObjectHandle object, uint32_t attrs_count);
static bool valid_object_max_size(object_type obj, uint32_t size); /* ok */
static int valid_obj_type_and_attr_count(object_type obj); /* ok */
static int get_attr_index(TEE_ObjectHandle object, uint32_t attributeID); /* ok */
static int gen_rsa_keypair(TEE_ObjectHandle obj, uint32_t key_size);
static int gen_10_key(TEE_ObjectHandle object, uint32_t keySize);
static int gen_dsa_keypair(TEE_ObjectHandle object, TEE_Attribute* params, uint32_t paramCount);
static int gen_dh_keypair(TEE_ObjectHandle object, TEE_Attribute* params, uint32_t paramCount);
static int bn2ref_to_obj(BIGNUM *bn, uint32_t ID, TEE_ObjectHandle obj, int i);
static int extract_attr_to_object(uint32_t ID, TEE_Attribute* params, uint32_t paramCount, TEE_ObjectHandle object, uint32_t index);
static int does_arr_contain_attrID(uint32_t ID, TEE_Attribute* attrs, uint32_t attrCount);
static int copy_obj_attr_to_obj(TEE_ObjectHandle srcObj, uint32_t attrID, TEE_ObjectHandle destObj, uint32_t destIndex);
static void openssl_cleanup();

static int query_for_access(void* objectID, size_t objectIDLen, size_t seek_access); /* place holder */
static void release_file(void* objectID, size_t objectIDLen); /* place holder */
static int is_object_id_in_use(void *objectID, size_t objectIDLen); /* place holder */

static int create_tables(sqlite3 *db_conn);
static int insert_user_data(sqlite3 *db_conn, void *objectID, size_t objectIDLen, void* initialData, size_t initialDataLen);
static int insert_object_handler(sqlite3 *db_conn, void* objectID, size_t objectIDLen, TEE_ObjectHandle obj);
static int insert_attributes(sqlite3 *db_conn, void *objectID, size_t objectIDLen, TEE_ObjectHandle obj);

static int load_object_handler(sqlite3 *db_conn, void *objectID, size_t objectIDLen, TEE_ObjectHandle obj);
static int load_attributes(sqlite3 *db_conn, void *objectID, size_t objectIDLen, TEE_ObjectHandle obj);
static int load_user_info(sqlite3 *db_conn, void *objectID, size_t objectIDLen, TEE_ObjectHandle obj);


/*
 * ## Non internal API functions ##
 */

static void openssl_cleanup()
{
	CRYPTO_cleanup_all_ex_data();
}

static int load_user_info(sqlite3 *db_conn, void *objectID, size_t objectIDLen, TEE_ObjectHandle obj)
{
	int sql_ret = SQLITE_OK;
	char *sql = "SELECT * FROM user_data WHERE id=?;";
	int i;
	sqlite3_stmt *stmt;

	sql_ret = sqlite3_prepare_v2(db_conn, sql, -1, &stmt, NULL);
	if(sql_ret != SQLITE_OK )
		goto err;

	sql_ret = sqlite3_bind_blob(stmt, 1, objectID, objectIDLen, SQLITE_TRANSIENT);
	if (sql_ret != SQLITE_OK)
		goto err;

	while ((sql_ret = sqlite3_step(stmt)) == SQLITE_ROW) {
		for (i = 0; i < sqlite3_column_count(stmt); ++i) {
			if (strcmp(sqlite3_column_name(stmt, i), "data") == 0) {
				obj->objectInfo.dataSize = sqlite3_column_bytes(stmt, i);
			}
		}
	}

	if (sql_ret != SQLITE_DONE)
		goto err;

	sqlite3_finalize(stmt);
	return sql_ret;

err:
	syslog(LOG_ERR, "Database error: %i : %s\n", sql_ret, sqlite3_errmsg(db_conn));
	return sql_ret;
}

static int load_attributes(sqlite3 *db_conn, void *objectID, size_t objectIDLen, TEE_ObjectHandle obj)
{
	int sql_ret = SQLITE_OK;
	int attr_count;
	char *sql = "SELECT * FROM attributes WHERE id=?;";
	int i;
	uint32_t rows = 0;
	sqlite3_stmt *stmt;

	attr_count = valid_obj_type_and_attr_count(obj->objectInfo.objectType);
	if (attr_count == -1)
		goto err_generic;

	/* Alloc memory for attributes (pointers) */
	obj->attrs = TEE_Malloc(attr_count * sizeof(TEE_Attribute), 0);
	if (obj->attrs == NULL)
		goto out_of_mem_attrs_ptr;
/*
	switch(obj->objectInfo.objectType) {
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
		if (!malloc_for_attrs(obj, attr_count))
			goto out_of_mem_attrs;
		break;

	case TEE_TYPE_DH_KEYPAIR:
		if (!malloc_for_attrs(obj, attr_count-1))
			goto out_of_mem_attrs;
		break;

	default:
		goto out_of_mem_attrs;
		break;
	}
*/
	sql_ret = sqlite3_prepare_v2(db_conn, sql, -1, &stmt, NULL);
	if(sql_ret != SQLITE_OK )
		goto db_err;

	sql_ret = sqlite3_bind_blob(stmt, 1, objectID, objectIDLen, SQLITE_TRANSIENT);
	if (sql_ret != SQLITE_OK)
		goto db_err;

	while ((sql_ret = sqlite3_step(stmt)) == SQLITE_ROW) {
		for (i = 0; i < sqlite3_column_count(stmt); ++i) {
			if (strcmp(sqlite3_column_name(stmt, i), "info") == 0) {
				memcpy(&obj->attrs[rows], sqlite3_column_blob(stmt, i), sqlite3_column_bytes(stmt, i));
			}

			if (strcmp(sqlite3_column_name(stmt, i), "content") == 0) {
				obj->attrs[rows].content.ref.buffer = TEE_Malloc(sqlite3_column_bytes(stmt, i), 0);
				if (obj->attrs[rows].content.ref.buffer == NULL)
					goto db_err;

				memcpy(obj->attrs[rows].content.ref.buffer, sqlite3_column_blob(stmt, i), sqlite3_column_bytes(stmt, i));
			}
		}
		++rows;
		if (rows > obj->attrs_count)
			goto db_err; /* should never ever get here */
	}

	if (sql_ret != SQLITE_DONE)
		goto db_err;

	sqlite3_finalize(stmt);
	return sql_ret;

db_err:
	free_attrs(obj);
	free(obj->attrs);
	syslog(LOG_ERR, "Database error: %i : %s\n", sql_ret, sqlite3_errmsg(db_conn));
	return sql_ret;

out_of_mem_attrs_ptr:
	syslog(LOG_ERR, "Out of memory\n");
	return TEE_ERROR_OUT_OF_MEMORY;

err_generic:
	syslog(LOG_ERR, "Something went wrong with persistant object attribute loading\n");
	return TEE_ERROR_GENERIC;
}

static int load_object_handler(sqlite3 *db_conn, void *objectID, size_t objectIDLen, TEE_ObjectHandle obj)
{
	char *sql = "SELECT * FROM object_handler WHERE id=?;";
	sqlite3_stmt *stmt;
	int i;
	const void *ret_handler;
	int sql_ret = SQLITE_OK;

	sql_ret = sqlite3_prepare_v2(db_conn, sql, -1, &stmt, NULL);
	if(sql_ret != SQLITE_OK )
		goto err;

	sql_ret = sqlite3_bind_blob(stmt, 1, objectID, objectIDLen, SQLITE_TRANSIENT);
	if (sql_ret != SQLITE_OK)
		goto err;

	while ((sql_ret = sqlite3_step(stmt)) == SQLITE_ROW) {
		for (i = 0; i < sqlite3_column_count(stmt); ++i) {
			if (!strcmp(sqlite3_column_name(stmt, i), "object_handler")) {
				ret_handler = sqlite3_column_blob(stmt, i);
				if (ret_handler != NULL)
					memcpy(obj, ret_handler, sizeof(struct __TEE_ObjectHandle));
			}
		}
	}

	sqlite3_finalize(stmt);
	return sql_ret;

err:
	syslog(LOG_ERR, "Database error: %i : %s\n", sql_ret, sqlite3_errmsg(db_conn));
	return sql_ret;
}

static int insert_user_data(sqlite3 *db_conn, void *objectID, size_t objectIDLen, void* initialData, size_t initialDataLen)
{
	char *sql = "INSERT INTO user_data (id, data) VALUES (?, ?);";
	sqlite3_stmt *stmt;
	int sql_ret = SQLITE_OK;

	if (db_conn == NULL)
		return TEE_ERROR_GENERIC;

	sql_ret = sqlite3_prepare_v2(db_conn, sql, -1, &stmt, NULL);
	if (sql_ret != SQLITE_OK)
		goto err;

	sql_ret = sqlite3_bind_blob(stmt, 1, objectID, objectIDLen, SQLITE_TRANSIENT);
	if (sql_ret != SQLITE_OK)
		goto err;

	if (initialData != NULL) {
		sql_ret = sqlite3_bind_blob(stmt, 2, initialData, initialDataLen, SQLITE_TRANSIENT);
		if (sql_ret != SQLITE_OK)
			goto err;
	}
	else {
		sql_ret = sqlite3_bind_zeroblob(stmt, 2, 0);
		if (sql_ret != SQLITE_OK)
			goto err;
	}

	sql_ret = sqlite3_step(stmt);
	if (sql_ret != SQLITE_DONE)
		goto err;

	sqlite3_finalize(stmt);
	return sql_ret;

err:
	syslog(LOG_ERR, "Database error: %i : %s\n", sql_ret, sqlite3_errmsg(db_conn));
	return sql_ret;
}


static int insert_attributes(sqlite3 *db_conn, void *objectID, size_t objectIDLen, TEE_ObjectHandle obj)
{
	char *sql = "INSERT INTO attributes (id, info, content) VALUES (?, ?, ?);";
	size_t i;
	sqlite3_stmt *stmt;
	int sql_ret = SQLITE_OK;

	if (db_conn == NULL)
		return TEE_ERROR_GENERIC;

	if (obj == NULL)
		return sql_ret;

	sql_ret = sqlite3_prepare_v2(db_conn, sql, -1, &stmt, NULL);
	if (sql_ret != SQLITE_OK)
		goto err;

	for (i = 0; i < obj->attrs_count; ++i) {
		sql_ret = sqlite3_bind_blob(stmt, 1, objectID, objectIDLen, SQLITE_TRANSIENT);
		if (sql_ret != SQLITE_OK)
			goto err;

		sql_ret = sqlite3_bind_blob(stmt, 2, &obj->attrs[i], sizeof(TEE_Attribute), SQLITE_TRANSIENT);
		if (sql_ret != SQLITE_OK)
			goto err;

		if (is_value_attribute(obj->attrs[i].attributeID)) {
			sql_ret = sqlite3_bind_null(stmt, 3);
			if (sql_ret != SQLITE_OK)
				goto err;
		}
		else {
			sql_ret = sqlite3_bind_blob(stmt, 3, obj->attrs[i].content.ref.buffer, obj->attrs[i].content.ref.length, SQLITE_TRANSIENT);
			if (sql_ret != SQLITE_OK)
				goto err;
		}

		sql_ret = sqlite3_step(stmt);
		if (sql_ret != SQLITE_DONE)
			goto err;

		sqlite3_reset(stmt);
	}

	sqlite3_finalize(stmt);
	return sql_ret;

err:
	syslog(LOG_ERR, "Database error: %i : %s\n", sql_ret, sqlite3_errmsg(db_conn));
	return sql_ret;
}

static int insert_object_handler(sqlite3 *db_conn, void *objectID, size_t objectIDLen, TEE_ObjectHandle obj)
{
	char *sql = "INSERT INTO object_handler (id, object_handler) VALUES (?, ?);";
	sqlite3_stmt *stmt;
	int sql_ret = SQLITE_OK;

	if (db_conn == NULL)
		return TEE_ERROR_GENERIC;

	sql_ret = sqlite3_prepare_v2(db_conn, sql, -1, &stmt, NULL);
	if (sql_ret != SQLITE_OK)
		goto err;

	sql_ret = sqlite3_bind_blob(stmt, 1, objectID, objectIDLen, SQLITE_TRANSIENT);
	if (sql_ret != SQLITE_OK)
		goto err;

	if (obj != NULL) {
		sql_ret = sqlite3_bind_blob(stmt, 2, obj, sizeof(struct __TEE_ObjectHandle), SQLITE_TRANSIENT);
		if (sql_ret != SQLITE_OK)
			goto err;

	}
	else {
		sql_ret = sqlite3_bind_null(stmt, 2);
		if (sql_ret != SQLITE_OK)
			goto err;
	}

	sql_ret = sqlite3_step(stmt);
	if (sql_ret != SQLITE_DONE)
		goto err;

	sqlite3_finalize(stmt);
	return sql_ret;

err:
	syslog(LOG_ERR, "Database error: %i : %s\n", sql_ret, sqlite3_errmsg(db_conn));
	return sql_ret;
}

static int create_tables(sqlite3 *db_conn)
{
	char *create_objec_handler = "CREATE TABLE IF NOT EXISTS object_handler (id BLOB PRIMARY KEY, object_handler BLOB);";
	char *create_user_data = "CREATE TABLE IF NOT EXISTS user_data (id BLOB PRIMARY KEY, data BLOB);";
	char *create_attributes = "CREATE TABLE IF NOT EXISTS attributes (id BLOB, info BLOB, content BLOB);";
	int sql_ret = SQLITE_OK;
	char *sql_err;

	if (db_conn == NULL)
		return TEE_ERROR_GENERIC;

	sql_ret = sqlite3_exec(db_conn, create_objec_handler, NULL, NULL, &sql_err);
	if (sql_ret != SQLITE_OK )
		goto err;

	sql_ret = sqlite3_exec(db_conn, create_user_data, NULL, NULL, &sql_err);
	if (sql_ret != SQLITE_OK )
		goto err;

	sql_ret = sqlite3_exec(db_conn, create_attributes, NULL, NULL, &sql_err);
	if (sql_ret != SQLITE_OK )
		goto err;

	return sql_ret;

err:
	syslog(LOG_ERR, "Database error: %i : %s\n", sql_ret, sql_err);
	sqlite3_free(sql_err);
	return sql_ret;
}

static void release_file(void* objectID, size_t objectIDLen)
{
	objectID = objectID;
	objectIDLen = objectIDLen;

	/* Do something.. call manager? :) */
}

static int query_for_access(void *objectID, size_t objectIDLen, size_t seek_access)
{
	/* TEST!! Emulate/simulate manager call.. */
	objectID = objectID;
	seek_access = seek_access;
	size_t i;
	char hex_ID[TEE_OBJECT_ID_MAX_LEN * 2 + 1];

	for (i = 0; i < objectIDLen; ++i)
		sprintf(hex_ID + i * 2, "%02x", *((unsigned char*)objectID + i));

	return 0;
}

static int is_object_id_in_use(void *objectID, size_t objectIDLen)
{
	objectID = objectID;
	objectIDLen = objectIDLen;

	/* TEST!! Emulate/simulate manager call.. */

	return 0;
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

		if (is_value_attribute(object->attrs[i].attributeID)) {
			object->attrs->content.value.a = 0;
			object->attrs->content.value.b = 0;
			continue;
		}

		object->attrs[i].content.ref.length = 0;
		free(object->attrs[i].content.ref.buffer);
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
		free_attrs(object);
		free(object->attrs);
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
	char hex_UUID[sizeof(TEE_UUID) * 2 + 1];
	sqlite3 *db;
	size_t i;
	int ret_val;
	char *db_name_with_path;

	/* test */
	void *test_UUID = (void*)UUID_test;
	/* test */

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

	if (query_for_access(objectID, objectIDLen, flags)) {
		/* This should also check, if objID exists */
		syslog(LOG_ERR, "Access conflict\n");
		return TEE_ERROR_ACCESS_CONFLICT;
	}

	/* Open connection to database */
	for (i = 0; i < sizeof(TEE_UUID); ++i)
		sprintf(hex_UUID + i * 2, "%02x", *((unsigned char*)test_UUID + i));

	if (asprintf(&db_name_with_path, "%s%s.db", DB_PATH, hex_UUID) == -1)
		goto out_of_mem_handler;

	if (sqlite3_open(db_name_with_path, &db) == -1) {
		syslog(LOG_ERR, "Can not connect or create database\n");
		free(db_name_with_path);
		return TEE_ERROR_GENERIC;
	}

	free(db_name_with_path);

	tmp_handle = TEE_Malloc(sizeof(struct __TEE_ObjectHandle), 0);
	if (tmp_handle == NULL)
		goto out_of_mem_handler;

	ret_val = load_object_handler(db, objectID, objectIDLen, tmp_handle);
	if (ret_val != SQLITE_OK && ret_val != SQLITE_DONE && ret_val != TEE_SUCCESS)
		goto load_err;

	ret_val = load_attributes(db, objectID, objectIDLen, tmp_handle);
	if (ret_val != SQLITE_OK && ret_val != SQLITE_DONE && ret_val != TEE_SUCCESS)
		goto load_err;

	ret_val = load_user_info(db, objectID, objectIDLen, tmp_handle);
	if (ret_val != SQLITE_OK && ret_val != SQLITE_DONE && ret_val != TEE_SUCCESS)
		goto load_err;

	memcpy(tmp_handle->per_obj_id, objectID, objectIDLen);
	tmp_handle->per_obj_id_len = objectIDLen;

	tmp_handle->objectInfo.handleFlags |= (TEE_HANDLE_FLAG_PERSISTENT | TEE_HANDLE_FLAG_INITIALIZED);
	*object = tmp_handle;
	sqlite3_close(db);

	return TEE_SUCCESS;

out_of_mem_handler:
	syslog(LOG_ERR, "Out of memory\n");
	sqlite3_close(db);
	return TEE_ERROR_OUT_OF_MEMORY;

load_err:
	free(tmp_handle);
	syslog(LOG_ERR, "Out of memory\n");
	sqlite3_close(db);
	return TEE_ERROR_GENERIC;
}

TEE_Result TEE_CreatePersistentObject(uint32_t storageID, void* objectID, size_t objectIDLen, uint32_t flags, TEE_ObjectHandle attributes, void* initialData, size_t initialDataLen, TEE_ObjectHandle* object)
{
	char hex_UUID[sizeof(TEE_UUID) * 2 + 1];
	sqlite3 *db;
	char *db_name_with_path;
	int sql_ret;
	char *sql_err;
	size_t i;
	uint32_t ret_val;

	/* test */
	void *test_UUID = (void*)UUID_test;
	/* test */

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

	if (query_for_access(objectID, objectIDLen, flags)) {
		syslog(LOG_ERR, "Access conflict\n");
		return TEE_ERROR_ACCESS_CONFLICT;
	}

	/* Open connection to database */
	for (i = 0; i < sizeof(TEE_UUID); ++i)
		sprintf(hex_UUID + i * 2, "%02x", *((unsigned char*)test_UUID + i));

	if (asprintf(&db_name_with_path, "%s%s.db", DB_PATH, hex_UUID) == -1) {
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	/* TEST !!! */
	//remove(db_name_with_path);
	/* TEST !!! */

	if (sqlite3_open(db_name_with_path, &db) == -1) {
		syslog(LOG_ERR, "Can not connect or create database\n");
		free(db_name_with_path);
		return TEE_ERROR_GENERIC;
	}

	free(db_name_with_path);

	/* Make more err checks */
	sql_ret = sqlite3_exec(db, "BEGIN IMMEDIATE;", NULL, NULL, &sql_err);
	if (sql_ret != SQLITE_OK)
		goto db_err;

	ret_val = create_tables(db);
	if (ret_val != SQLITE_OK && ret_val != SQLITE_DONE && ret_val != TEE_SUCCESS)
		goto func_err;

	ret_val = insert_object_handler(db, objectID, objectIDLen, attributes);
	if (ret_val != SQLITE_OK && ret_val != SQLITE_DONE && ret_val != TEE_SUCCESS)
		goto func_err;

	ret_val = insert_attributes(db, objectID, objectIDLen, attributes);
	if (ret_val != SQLITE_OK && ret_val != SQLITE_DONE && ret_val != TEE_SUCCESS)
		goto func_err;

	ret_val = insert_user_data(db, objectID, objectIDLen, initialData, initialDataLen);
	if (ret_val != SQLITE_OK && ret_val != SQLITE_DONE && ret_val != TEE_SUCCESS)
		goto func_err;

	/* Make more err checks */
	sql_ret = sqlite3_exec(db, "COMMIT;", NULL, NULL, &sql_err);
	if (sql_ret != SQLITE_OK)
		goto db_err;

	sqlite3_close(db);

	if (object != NULL) {
		/* open v2 */
	}
	else {
		release_file(objectID, objectIDLen);
	}

	return TEE_SUCCESS;

db_err:
	syslog(LOG_ERR, "Database error: %i : %s\n", sql_ret, sql_err);
	sqlite3_free(sql_err);

func_err:
	sqlite3_exec(db, "ROLLBACK", 0, 0, 0);
	sqlite3_close(db);
	release_file(objectID, objectIDLen);

	/* Error has been logged and this is notification to user */
	if (ret_val == SQLITE_FULL)
		return TEE_ERROR_STORAGE_NO_SPACE;

	if (ret_val == SQLITE_NOMEM)
		return TEE_ERROR_OUT_OF_MEMORY;

	if (ret_val == TEE_ERROR_OUT_OF_MEMORY)
		return TEE_ERROR_OUT_OF_MEMORY;

	return TEE_ERROR_GENERIC;
}

TEE_Result TEE_RenamePersistentObject(TEE_ObjectHandle object, void* newObjectID, size_t newObjectIDLen)
{
	char *update_objec_handler = "UPDATE object_handler SET id=? WHERE id=?;";
	char *update_user_data = "UPDATE user_data SET id=? WHERE id=?;";
	char *update_attributes = "UPDATE attributes SET id=? WHERE id=?;";
	sqlite3_stmt *stmt_update_objec_handler;
	sqlite3_stmt *stmt_update_user_data;
	sqlite3_stmt *stmt_update_attributes;
	char hex_UUID[sizeof(TEE_UUID) * 2 + 1];
	sqlite3 *db;
	char *db_name_with_path;
	int sql_ret;
	char *sql_err;
	size_t i;

	/* test */
	void *test_UUID = (void*)UUID_test;
	/* test */

	if (object == NULL || !(object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)) {
		syslog(LOG_ERR, "ObjectID buffer is NULL or not persistant object\n");
		return TEE_ERROR_GENERIC; /* replace to panic(), when implemented */
	}

	if (newObjectIDLen > TEE_OBJECT_ID_MAX_LEN) {
		return TEE_ERROR_GENERIC; /* replace to panic(), when implemented */
	}

	if (object != NULL && !(object->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED)) {
		return TEE_ERROR_GENERIC; /* replace to panic(), when implemented */
	}

	if (query_for_access(object->per_obj_id, object->per_obj_id_len, TEE_DATA_FLAG_ACCESS_WRITE_META)) {
		syslog(LOG_ERR, "Access conflict\n");
		return TEE_ERROR_ACCESS_CONFLICT;
	}

	if (is_object_id_in_use(newObjectID, newObjectIDLen)) {
		syslog(LOG_ERR, "Access conflict: ID exists\n");
		return TEE_ERROR_ACCESS_CONFLICT;
	}

	/* Open connection to database */
	for (i = 0; i < sizeof(TEE_UUID); ++i)
		sprintf(hex_UUID + i * 2, "%02x", *((unsigned char*)test_UUID + i));

	if (asprintf(&db_name_with_path, "%s%s.db", DB_PATH, hex_UUID) == -1) {
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	if (sqlite3_open(db_name_with_path, &db) == -1) {
		syslog(LOG_ERR, "Can not connect or create database\n");
		free(db_name_with_path);
		return TEE_ERROR_GENERIC;
	}

	free(db_name_with_path);

	/* Object handler table */
	sql_ret = sqlite3_exec(db, "BEGIN IMMEDIATE;", NULL, NULL, &sql_err);
	if (sql_ret != SQLITE_OK)
		goto db_err;

	sql_ret = sqlite3_prepare_v2(db, update_objec_handler, -1, &stmt_update_objec_handler, NULL);
	if(sql_ret != SQLITE_OK )
		goto err;

	sql_ret = sqlite3_bind_blob(stmt_update_objec_handler, 1, newObjectID, newObjectIDLen, SQLITE_TRANSIENT);
	if (sql_ret != SQLITE_OK)
		goto err;

	sql_ret = sqlite3_bind_blob(stmt_update_objec_handler, 2, object->per_obj_id, object->per_obj_id_len, SQLITE_TRANSIENT);
	if (sql_ret != SQLITE_OK)
		goto err;

	sql_ret = sqlite3_step(stmt_update_objec_handler);
	if (sql_ret != SQLITE_DONE)
		goto err;

	sqlite3_finalize(stmt_update_objec_handler);

	/* Attributes table */
	sql_ret = sqlite3_prepare_v2(db, update_attributes, -1, &stmt_update_attributes, NULL);
	if(sql_ret != SQLITE_OK )
		goto err;

	sql_ret = sqlite3_bind_blob(stmt_update_attributes, 1, newObjectID, newObjectIDLen, SQLITE_TRANSIENT);
	if (sql_ret != SQLITE_OK)
		goto err;

	sql_ret = sqlite3_bind_blob(stmt_update_attributes, 2, object->per_obj_id, object->per_obj_id_len, SQLITE_TRANSIENT);
	if (sql_ret != SQLITE_OK)
		goto err;

	sql_ret = sqlite3_step(stmt_update_attributes);
	if (sql_ret != SQLITE_DONE)
		goto err;

	sqlite3_finalize(stmt_update_attributes);

	/* User data table */
	sql_ret = sqlite3_prepare_v2(db, update_user_data, -1, &stmt_update_user_data, NULL);
	if(sql_ret != SQLITE_OK )
		goto err;

	sql_ret = sqlite3_bind_blob(stmt_update_user_data, 1, newObjectID, newObjectIDLen, SQLITE_TRANSIENT);
	if (sql_ret != SQLITE_OK)
		goto err;

	sql_ret = sqlite3_bind_blob(stmt_update_user_data, 2, object->per_obj_id, object->per_obj_id_len, SQLITE_TRANSIENT);
	if (sql_ret != SQLITE_OK)
		goto err;

	sql_ret = sqlite3_step(stmt_update_user_data);
	if (sql_ret != SQLITE_DONE)
		goto err;

	sqlite3_finalize(stmt_update_user_data);

	sql_ret = sqlite3_exec(db, "COMMIT;", NULL, NULL, &sql_err);
	if (sql_ret != SQLITE_OK)
		goto db_err;

	sqlite3_close(db);
	release_file(object->per_obj_id, object->per_obj_id_len);

	memcpy(object->per_obj_id, newObjectID, newObjectIDLen);
	object->per_obj_id_len = newObjectIDLen;

	return TEE_SUCCESS;

err:
	syslog(LOG_ERR, "Database error: %i : %s\n", sql_ret, sqlite3_errmsg(db));
	return TEE_ERROR_GENERIC;

db_err:
	sqlite3_exec(db, "ROLLBACK", 0, 0, 0);
	syslog(LOG_ERR, "Database error: %i : %s\n", sql_ret, sql_err);
	sqlite3_free(sql_err);
	sqlite3_close(db);
	release_file(object->per_obj_id, object->per_obj_id_len);
	return TEE_ERROR_GENERIC;
}

void TEE_CloseAndDeletePersistentObject(TEE_ObjectHandle object)
{
	char *delete_objec_handler = "DELETE FROM object_handler WHERE id=?;";
	char *delete_user_data = "DELETE FROM user_data WHERE id=?;";
	char *delete_attributes = "DELETE FROM attributes WHERE id=?;";
	sqlite3_stmt *stmt_delete_objec_handler;
	sqlite3_stmt *stmt_delete_user_data;
	sqlite3_stmt *stmt_delete_attributes;
	char hex_UUID[sizeof(TEE_UUID) * 2 + 1];
	sqlite3 *db;
	char *db_name_with_path;
	int sql_ret;
	char *sql_err;
	size_t i;

	/* test */
	void *test_UUID = (void*)UUID_test;
	/* test */

	if (object == NULL || !(object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)) {
		syslog(LOG_ERR, "ObjectID buffer is NULL or not persistant object\n");
		return; /* replace to panic(), when implemented */
	}

	if (query_for_access(object->per_obj_id, object->per_obj_id_len, TEE_DATA_FLAG_ACCESS_WRITE_META)) {
		syslog(LOG_ERR, "Access conflict\n");
		return ;
	}

	/* Open connection to database */
	for (i = 0; i < sizeof(TEE_UUID); ++i)
		sprintf(hex_UUID + i * 2, "%02x", *((unsigned char*)test_UUID + i));

	if (asprintf(&db_name_with_path, "%s%s.db", DB_PATH, hex_UUID) == -1) {
		return;
	}

	if (sqlite3_open(db_name_with_path, &db) == -1) {
		syslog(LOG_ERR, "Can not connect or create database\n");
		free(db_name_with_path);
		return;
	}

	free(db_name_with_path);

	/* Object handler table */
	sql_ret = sqlite3_exec(db, "BEGIN IMMEDIATE;", NULL, NULL, &sql_err);
	if (sql_ret != SQLITE_OK)
		goto db_err;

	sql_ret = sqlite3_prepare_v2(db, delete_objec_handler, -1, &stmt_delete_objec_handler, NULL);
	if(sql_ret != SQLITE_OK )
		goto err;

	sql_ret = sqlite3_bind_blob(stmt_delete_objec_handler, 1, &object->per_obj_id, object->per_obj_id_len, SQLITE_TRANSIENT);
	if (sql_ret != SQLITE_OK)
		goto err;

	sql_ret = sqlite3_step(stmt_delete_objec_handler);
	if (sql_ret != SQLITE_DONE)
		goto err;

	sqlite3_finalize(stmt_delete_objec_handler);

	/* Attributes table */
	sql_ret = sqlite3_prepare_v2(db, delete_attributes, -1, &stmt_delete_attributes, NULL);
	if(sql_ret != SQLITE_OK )
		goto err;

	sql_ret = sqlite3_bind_blob(stmt_delete_attributes, 1, &object->per_obj_id, object->per_obj_id_len, SQLITE_TRANSIENT);
	if (sql_ret != SQLITE_OK)
		goto err;

	sql_ret = sqlite3_step(stmt_delete_attributes);
	if (sql_ret != SQLITE_DONE)
		goto err;

	sqlite3_finalize(stmt_delete_attributes);

	/* User data table */
	sql_ret = sqlite3_prepare_v2(db, delete_user_data, -1, &stmt_delete_user_data, NULL);
	if(sql_ret != SQLITE_OK )
		goto err;

	sql_ret = sqlite3_bind_blob(stmt_delete_user_data, 1, &object->per_obj_id, object->per_obj_id_len, SQLITE_TRANSIENT);
	if (sql_ret != SQLITE_OK)
		goto err;

	sql_ret = sqlite3_step(stmt_delete_user_data);
	if (sql_ret != SQLITE_DONE)
		goto err;

	sqlite3_finalize(stmt_delete_user_data);

	sql_ret = sqlite3_exec(db, "COMMIT;", NULL, NULL, &sql_err);
	if (sql_ret != SQLITE_OK)
		goto db_err;

	sqlite3_close(db);
	release_file(object->per_obj_id, object->per_obj_id_len);

	TEE_CloseObject(object);

	return;

err:
	syslog(LOG_ERR, "Database error: %i : %s\n", sql_ret, sqlite3_errmsg(db));
	return;

db_err:
	sqlite3_exec(db, "ROLLBACK", 0, 0, 0);
	syslog(LOG_ERR, "Database error: %i : %s\n", sql_ret, sql_err);
	sqlite3_free(sql_err);
	sqlite3_close(db);
	release_file(object->per_obj_id, object->per_obj_id_len);
	return;
}

/* TEST !! */
int main() {
	printf(" ## Starting ##\n");

	openlog(NULL, 0, 0);

	TEE_Result ret;
	TEE_ObjectHandle handler;
	TEE_ObjectHandle handler2;
	TEE_ObjectHandle han;
	TEE_ObjectHandle han2;
	size_t key_size = 256;
	char objID[] = "56c5d1b260704de30fe7af67e5b9327613abebe6172a2b4e949d84b8e561e2fb";
	char objID2[] = "65c5d1b260704de30fe7af67e5b9327613abebe6172a2b4e949d84b8e561e2fb";
	size_t objID_len = 64;
	uint32_t flags = 0xffffffff ^ TEE_DATA_FLAG_EXCLUSIVE;
	void * data;
	size_t data_len = 12;
	size_t i, j;

	data = malloc(data_len);
	if (data == NULL)
		return 0;
	RAND_bytes(data, data_len);

	ret = TEE_AllocateTransientObject(TEE_TYPE_AES, key_size, &handler);
	if (ret == TEE_ERROR_OUT_OF_MEMORY) {
		printf("Fail: no mem\n");
		return 0;
	}

	if (ret == TEE_ERROR_NOT_SUPPORTED) {
		printf("Fail: no sup\n");
		free(data);
		return 0;
	}

	ret = TEE_GenerateKey(handler, key_size, NULL, 0);
	if (ret != TEE_SUCCESS) {
		printf("Fail: bad para\n");
		return 0;
	}

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, objID_len, flags, handler, data, data_len, NULL);
	if (ret != TEE_SUCCESS) {
		printf("Fail: per creation\n");
		return 0;
	}

	ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, objID_len, flags, &handler2);
	if (ret != TEE_SUCCESS) {
		printf("Fail: per open\n");
		return 0;
	}
/*
	for (j = 0; j < handler->attrs_count; j++) {
		printf("org: ");
		for (i = 0; i < handler->attrs[j].content.ref.length; i++) {
			printf("%02x", ((unsigned char *) handler->attrs[j].content.ref.buffer) [i]);
		}
		printf("\n");
		printf("ret: ");
		for (i = 0; i < handler2->attrs[j].content.ref.length; i++) {
			printf("%02x", ((unsigned char *) handler2->attrs[j].content.ref.buffer) [i]);
		}
		printf("\n");
	}
*/
	TEE_CloseObject(handler);
	TEE_CloseAndDeletePersistentObject(handler2);

	/* Another one */
	ret = TEE_AllocateTransientObject(TEE_TYPE_AES, key_size, &han);
	if (ret == TEE_ERROR_OUT_OF_MEMORY) {
		printf("Fail: no mem\n");
		return 0;
	}

	if (ret == TEE_ERROR_NOT_SUPPORTED) {
		printf("Fail: no sup\n");
		free(data);
		return 0;
	}

	ret = TEE_GenerateKey(han, key_size, NULL, 0);
	if (ret != TEE_SUCCESS) {
		printf("Fail: bad para\n");
		return 0;
	}

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)objID2, objID_len, flags, han, data, data_len, NULL);
	if (ret != TEE_SUCCESS) {
		printf("Fail: per creation\n");
		return 0;
	}

	ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, (void *)objID2, objID_len, flags, &han2);
	if (ret != TEE_SUCCESS) {
		printf("Fail: per open\n");
		return 0;
	}
/*
	for (j = 0; j < handler->attrs_count; j++) {
		printf("org: ");
		for (i = 0; i < handler->attrs[j].content.ref.length; i++) {
			printf("%02x", ((unsigned char *) handler->attrs[j].content.ref.buffer) [i]);
		}
		printf("\n");
		printf("ret: ");
		for (i = 0; i < handler2->attrs[j].content.ref.length; i++) {
			printf("%02x", ((unsigned char *) handler2->attrs[j].content.ref.buffer) [i]);
		}
		printf("\n");
	}
*/

	TEE_CloseObject(han);
	TEE_CloseObject(han2);

	free(data);

	closelog();

	return 1;
}












