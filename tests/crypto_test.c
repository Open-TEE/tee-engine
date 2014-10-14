/*****************************************************************************
** Copyright (C) 2013 Secure Systems Group.                                 **
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

/* Extreme simply smoke tests. If something than function name is printed -> FAIL */

#include <stdio.h>
#include <syslog.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "../include/tee_internal_api.h"
#include "../internal_api/tee_object_handle.h"

 /* Useful functions */
static void pri_obj_attr(TEE_ObjectHandle object);
static void pri_and_cmp_attr(TEE_ObjectHandle obj1, TEE_ObjectHandle obj2);
static void pri_void_buf(void *buf, size_t len);
static void pri_obj_data(TEE_ObjectHandle object);
static void pri_obj_info(TEE_ObjectInfo info);
static void gen_RSA_per_obj_with_data(TEE_ObjectHandle *gen_obj, size_t data_len);
static void gen_rand_per_data_obj(TEE_ObjectHandle *gen_obj, size_t data_len);
static void free_attr(TEE_Attribute *params, size_t count);

#define KEY_IN_BYTES(key_in_bits) ((key_in_bits + 7) / 8)

/* pri_obj_attr */
static void __attribute__((unused)) pri_obj_attr(TEE_ObjectHandle object) /* No warning */
{
	size_t i,j;
	if (object == NULL)
		return;

	for (i = 0; i < object->attrs_count; ++i) {
		for (j = 0; j < object->attrs[i].content.ref.length; j++) {
			printf("%02x", ((unsigned char *) object->attrs[i].content.ref.buffer) [j]);
		}
		printf("\n");
	}
}

/* pri_and_cmp_attr */
static void __attribute__((unused)) pri_and_cmp_attr(TEE_ObjectHandle obj1, TEE_ObjectHandle obj2)
{
	size_t i,j, attr_count, cmp_len;

	if (obj1 == NULL || obj2 == NULL)
		return;

	if (obj1 > obj2)
		attr_count = obj1->attrs_count;
	else
		attr_count = obj2->attrs_count;

	printf("obj1: %d\n", obj1->attrs_count);
	printf("obj2: %d\n", obj2->attrs_count);

	for (i = 0; i < attr_count; ++i) {
		if (obj1->attrs_count > i) {
			printf("obj1: ");
			for (j = 0; j < obj1->attrs[i].content.ref.length; j++)
				printf("%02x", ((unsigned char *) obj1->attrs[i].content.ref.buffer) [j]);
		} else {
			printf("obj1: -");
		}
		if (obj2->attrs_count > i) {
			printf("\nobj2: ");
			for (j = 0; j < obj2->attrs[i].content.ref.length; j++)
				printf("%02x", ((unsigned char *) obj2->attrs[i].content.ref.buffer) [j]);
		} else {
			printf("\nobj2: -");
		}

		printf("\nCmp: ");

		if (obj1->attrs_count == obj2->attrs_count) {
			if (obj1->attrs[i].content.ref.length > obj2->attrs[i].content.ref.length)
				cmp_len = obj1->attrs[i].content.ref.length;
			else
				cmp_len = obj2->attrs[i].content.ref.length;

			if (!bcmp(obj1->attrs[i].content.ref.buffer, obj2->attrs[i].content.ref.buffer, cmp_len))
				printf("Same1 \n");
			else
				printf("NO\n");
		} else {
			printf("can not cmp\n");
		}
	}
}

static void pri_void_buf(void *buf, size_t len)
{
	if (buf == NULL)
		return;

	size_t i;
	for (i = 0; i < len; ++i)
		printf("%02x", ((unsigned char *) buf) [i]);
	printf("\n");
}

static void __attribute__((unused)) pri_obj_data(TEE_ObjectHandle object)
{
	void *data = NULL;
	TEE_ObjectInfo info;
	uint32_t cur_pos;
	TEE_Result ret;
	uint32_t count = 0;

	if (object == NULL)
		return;

	TEE_GetObjectInfo(object, &info);

	data = calloc(1, info.dataSize);
	if (data == NULL) {
		printf("Fail: pri_obj_data(mem)\n");
	}

	cur_pos = info.dataPosition;

	ret = TEE_SeekObjectData(object, 0, TEE_DATA_SEEK_SET);
	if (ret != TEE_SUCCESS) {
		printf("Fail: pri_obj_data(seek beginning)\n");
		goto err;
	}

	ret = TEE_ReadObjectData(object, data, info.dataSize, &count);
	if (ret != TEE_SUCCESS || count != info.dataSize) {
		printf("Fail: pri_obj_data(read)\n");
		goto err;
	}

	ret = TEE_SeekObjectData(object, cur_pos, TEE_DATA_SEEK_SET);
	if (ret != TEE_SUCCESS) {
		printf("Fail: pri_obj_data(set back prev pos)\n");
		goto err;
	}

	pri_void_buf(data, info.dataSize);

err:
	free(data);
}

static void __attribute__((unused)) pri_obj_info(TEE_ObjectInfo info)
{
	printf("Info structure:\n");
	printf("dataPosition:  %u\n", info.dataPosition);
	printf("dataSize:      %u\n", info.dataSize);
	printf("handleFlags:   %u\n", info.handleFlags);
	printf("maxObjectSize: %u\n", info.maxObjectSize);
	printf("objectSize:    %u\n", info.objectSize);
	printf("objectType:    %u\n", info.objectType);
	printf("objectUsage:   %u\n", info.objectUsage);
}

static void free_attr(TEE_Attribute *params, size_t count)
{
	size_t i;

	if (params == NULL)
		return;

	for (i = 0; i < count; ++i)
		free(params[i].content.ref.buffer);
}

static void __attribute__((unused)) gen_rand_per_data_obj(TEE_ObjectHandle *gen_obj, size_t data_len)
{
	void *ID = NULL;
	size_t ID_len = 30;
	uint32_t flags = 0xffffffff ^ TEE_DATA_FLAG_EXCLUSIVE;
	void * init_data = NULL;
	TEE_Result ret;

	init_data = malloc(data_len);
	if (init_data == NULL) {
		printf("Fail: gen_rand_data_obj(inti_data mem)\n");
		goto err;
	}
	RAND_bytes(init_data, data_len);

	ID = malloc(ID_len);
	if (ID == NULL) {
		printf("Fail: gen_rand_data_obj(inti_data mem)\n");
		goto err;
	}
	RAND_bytes(ID, ID_len);

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)ID, ID_len, flags, NULL, init_data, data_len, gen_obj);
	if (ret != TEE_SUCCESS) {
		printf("Fail: gen_rand_data_obj(per create)\n");
		goto err;
	}

err:
	free(ID);
	free(init_data);
}

static void __attribute__((unused)) gen_RSA_per_obj_with_data(TEE_ObjectHandle *gen_obj, size_t data_len)
{
	TEE_Result ret;
	TEE_ObjectHandle handler;
	uint32_t key_size = 512;
	void *ID = NULL;
	uint32_t ID_len = 30;
	uint32_t flags = 0xffffffff ^ TEE_DATA_FLAG_EXCLUSIVE;
	void * init_data;

	init_data = malloc(data_len);
	if (init_data == NULL) {
		printf("Fail: gen_rand_data_obj(inti_data mem)\n");
		goto err;
	}
	RAND_bytes(init_data, data_len);

	ID = malloc(ID_len);
	if (ID == NULL) {
		printf("Fail: gen_rand_data_obj(ID mem)\n");
		goto err;
	}
	RAND_bytes(ID, ID_len);

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &handler);
	if (ret != TEE_SUCCESS) {
		printf("Fail: gen_RSA_per_obj_with_data(alloc)\n");
		goto err;
	}

	ret = TEE_GenerateKey(handler, key_size, NULL, 0);
	if (ret != TEE_SUCCESS) {
		printf("Fail: gen_RSA_per_obj_with_data(gen key)\n");
		goto err;
	}

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, ID, ID_len, flags, handler, init_data, data_len, gen_obj);
	if (ret != TEE_SUCCESS) {
		printf("Fail: gen_RSA_per_obj_with_data(per create)\n");
		goto err;
	}

err:
	TEE_FreeTransientObject(handler);
	free(ID);
	free(init_data);
}

static void set_RSA_key_to_operation()
{
	printf("  ####   set_RSA_key_to_operation   ####\n");

	TEE_Result ret;
	TEE_ObjectHandle key = NULL;
	uint32_t key_size = 512;
	TEE_OperationHandle operation = NULL;

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &key);
	if (ret != TEE_SUCCESS) {
		printf("Fail: transient alloc\n");
		goto err;
	}

	ret = TEE_GenerateKey(key, key_size, NULL, 0);
	if (ret != TEE_SUCCESS) {
		printf("Fail: gen key\n");
		goto err;
	}

	ret = TEE_AllocateOperation(&operation, TEE_ALG_RSA_NOPAD, TEE_MODE_ENCRYPT, key_size);
	if (ret != TEE_SUCCESS) {
		printf("Fail: alloc enc handle\n");
		goto err;
	}

	ret = TEE_SetOperationKey(operation, key);
	if (ret != TEE_SUCCESS) {
		printf("Fail: set op key\n");
		goto err;
	}

err:
	TEE_FreeTransientObject(key);
	TEE_FreeOperation(operation);
}

static void AES_256_xts_enc_and_dec()
{
	printf("  ####   AES_256_xts_enc_and_dec   ####\n");

	TEE_Result ret;
	size_t key_size = 256;
	TEE_ObjectHandle key1 = NULL;
	TEE_ObjectHandle key2 = NULL;
	TEE_OperationHandle enc_handle = NULL;
	TEE_OperationHandle dec_handle = NULL;

	void *plain = NULL;
	void *cipher = NULL;
	void *IV = NULL;
	void *dec_plain = NULL;

	uint32_t plain_len = 100;
	uint32_t cipher_len = plain_len + 800; /* +1 if you like add \n */
	uint32_t dec_plain_len = 100;
	uint32_t IVlen = key_size;

	uint32_t write_bytes = 0;
	uint32_t write_to_cipher = 0;
	uint32_t write_to_dec_plain = 0;

	IV = TEE_Malloc(IVlen, 0);
	plain = TEE_Malloc(plain_len, 0);
	cipher = TEE_Malloc(cipher_len, 0);
	dec_plain = TEE_Malloc(dec_plain_len, 0);
	if (!IV || !plain || !cipher || !dec_plain) {
		printf("Fail: IV || plain || cipher || dec_plain alloc\n");
		goto err;
	}
	RAND_bytes(IV, IVlen);
	RAND_bytes(plain, plain_len);

	/* Alloc and gen keys */
	ret = TEE_AllocateTransientObject(TEE_TYPE_AES, key_size, &key1);
	if (ret != TEE_SUCCESS) {
		printf("Fail: transient alloc key1\n");
		goto err;
	}

	ret = TEE_AllocateTransientObject(TEE_TYPE_AES, key_size, &key2);
	if (ret != TEE_SUCCESS) {
		printf("Fail: transient alloc key2\n");
		goto err;
	}

	ret = TEE_GenerateKey(key1, key_size, NULL, 0);
	if (ret != TEE_SUCCESS) {
		printf("Fail: gen key1\n");
		goto err;
	}

	ret = TEE_GenerateKey(key2, key_size, NULL, 0);
	if (ret != TEE_SUCCESS) {
		printf("Fail: gen key2\n");
		goto err;
	}

	/* Alloc operation and set key */
	ret = TEE_AllocateOperation(&enc_handle, TEE_ALG_AES_XTS, TEE_MODE_ENCRYPT, key_size);
	if (ret != TEE_SUCCESS) {
		printf("Fail: alloc enc handle\n");
		goto err;
	}

	ret = TEE_AllocateOperation(&dec_handle, TEE_ALG_AES_XTS, TEE_MODE_DECRYPT, key_size);
	if (ret != TEE_SUCCESS) {
		printf("Fail: alloc dec handle\n");
		goto err;
	}

	ret = TEE_SetOperationKey2(enc_handle, key1, key2);
	if (ret != TEE_SUCCESS) {
		printf("Fail: set enc key\n");
		goto err;
	}

	ret = TEE_SetOperationKey2(dec_handle, key1, key2);
	if (ret != TEE_SUCCESS) {
		printf("Fail: set dec key\n");
		goto err;
	}

	/* Init ciphers */
	TEE_CipherInit(enc_handle, IV, IVlen);
	TEE_CipherInit(dec_handle, IV, IVlen);

	/* Decrypt */
	write_bytes = cipher_len;
	ret = TEE_CipherUpdate(enc_handle, plain, plain_len, cipher, &write_bytes);
	if (ret != TEE_SUCCESS) {
		printf("Fail: update enc\n");
		goto err;
	}

	write_to_cipher += write_bytes;
	write_bytes = cipher_len - write_to_cipher;
	ret = TEE_CipherDoFinal(enc_handle, NULL, 0,
				(unsigned char *)cipher + write_to_cipher, &write_bytes);
	if (ret != TEE_SUCCESS) {
		printf("Fail: update enc\n");
		goto err;
	}

	cipher_len = write_to_cipher + write_bytes;

	/* Encrypt */
	write_bytes = dec_plain_len;
	ret = TEE_CipherUpdate(dec_handle, cipher, cipher_len, dec_plain, &write_bytes);
	if (ret != TEE_SUCCESS) {
		printf("Fail: update enc\n");
		goto err;
	}

	write_to_dec_plain += write_bytes;

	write_bytes = dec_plain_len - write_to_dec_plain;
	ret = TEE_CipherDoFinal(dec_handle, NULL, 0,
				(unsigned char *)dec_plain + write_to_dec_plain, &write_bytes);
	if (ret != TEE_SUCCESS) {
		printf("Fail: update enc\n");
		goto err;
	}

	dec_plain_len = write_to_dec_plain + write_bytes;

	if (bcmp(dec_plain, plain, write_to_dec_plain)) {
		printf("Fail: can't dec from enc\n");
		goto err;
	}

err:
	TEE_FreeTransientObject(key1);
	TEE_FreeTransientObject(key2);
	TEE_FreeOperation(enc_handle);
	TEE_FreeOperation(dec_handle);
	TEE_Free(IV);
	TEE_Free(cipher);
	TEE_Free(plain);
	TEE_Free(dec_plain);
}

static bool warp_sym_enc(TEE_ObjectHandle key, void *IV, size_t IV_len, uint32_t alg,
		     void *plain, size_t plain_len, void *cipher, size_t *cipher_len)
{
	TEE_Result ret;
	TEE_OperationHandle enc_handle = NULL;
	uint32_t write_bytes = 0;
	uint32_t total_write_bytes = 0;
	TEE_ObjectInfo info;

	TEE_GetObjectInfo(key, &info);

	ret = TEE_AllocateOperation(&enc_handle, alg, TEE_MODE_ENCRYPT, info.maxObjectSize);
	if (ret != TEE_SUCCESS) {
		printf("Fail: alloc enc handle\n");
		goto err;
	}

	ret = TEE_SetOperationKey(enc_handle, key);
	if (ret != TEE_SUCCESS) {
		printf("Fail: set enc key\n");
		goto err;
	}

	TEE_CipherInit(enc_handle, IV, IV_len);

	write_bytes = *cipher_len;

	ret = TEE_CipherUpdate(enc_handle, plain, plain_len, cipher, &write_bytes);
	if (ret != TEE_SUCCESS) {
		printf("Fail: update enc\n");
		goto err;
	}

	total_write_bytes += write_bytes;
	write_bytes = *cipher_len - total_write_bytes;

	ret = TEE_CipherDoFinal(enc_handle, NULL, 0,
				(unsigned char *)cipher + total_write_bytes, &write_bytes);
	if (ret != TEE_SUCCESS) {
		printf("Fail: final enc\n");
		goto err;
	}

	*cipher_len = total_write_bytes + write_bytes;

	TEE_FreeOperation(enc_handle);
	return true;
err:
	TEE_FreeOperation(enc_handle);
	return false;
}

static bool warp_sym_dec(TEE_ObjectHandle key, void *IV, size_t IV_len, uint32_t alg,
			 void *cipher, size_t cipher_len, void *plain, size_t *plain_len)
{
	TEE_Result ret = TEE_SUCCESS;
	TEE_OperationHandle dec_handle = NULL;
	uint32_t write_bytes = 0;
	uint32_t total_write_bytes = 0;
	TEE_ObjectInfo info;

	TEE_GetObjectInfo(key, &info);

	ret = TEE_AllocateOperation(&dec_handle, alg, TEE_MODE_DECRYPT, info.maxObjectSize);
	if (ret != TEE_SUCCESS) {
		printf("Fail: alloc dec handle\n");
		goto err;
	}

	ret = TEE_SetOperationKey(dec_handle, key);
	if (ret != TEE_SUCCESS) {
		printf("Fail: set dec key\n");
		goto err;
	}

	TEE_CipherInit(dec_handle, IV, IV_len);

	write_bytes = *plain_len;

	ret = TEE_CipherUpdate(dec_handle, cipher, cipher_len, plain, &write_bytes);
	if (ret != TEE_SUCCESS) {
		printf("Fail: update dec\n");
		goto err;
	}

	total_write_bytes += write_bytes;
	write_bytes = *plain_len - total_write_bytes;

	ret = TEE_CipherDoFinal(dec_handle, NULL, 0,
				(unsigned char *)plain + total_write_bytes, &write_bytes);
	if (ret != TEE_SUCCESS) {
		printf("Fail: final dec\n");
		goto err;
	}

	*plain_len = total_write_bytes + write_bytes;

	TEE_FreeOperation(dec_handle);
	return true;
err:
	TEE_FreeOperation(dec_handle);
	return false;
}

static void des3_cbc_enc_dec()
{
	printf("  ####   des3_cbc_enc_dec   ####\n");

	TEE_Result ret = TEE_SUCCESS;
	size_t key_size = 56;
	uint32_t obj_type = TEE_TYPE_DES;
	uint32_t alg = TEE_ALG_DES_ECB_NOPAD;
	TEE_ObjectHandle key = NULL;
	char *plain_msg = "TANEL";

	size_t plain_len = 8;
	size_t cipher_len = 8+8;
	size_t dec_plain_len = plain_len;
	size_t IVlen = key_size + 16;

	void *plain = NULL;
	void *cipher = NULL;
	void *dec_plain = NULL;
	void *IV = NULL;

	size_t write_to_cipher = 0;
	size_t write_to_dec_plain = 0;

	IV = TEE_Malloc(IVlen, 0);
	plain = TEE_Malloc(plain_len, 0);
	cipher = TEE_Malloc(cipher_len, 0);
	dec_plain = TEE_Malloc(dec_plain_len, 0);
	if (!IV || !plain || !cipher || !dec_plain) {
		printf("Fail: IV || plain || cipher alloc || dec_plain\n");
		goto err;
	}
	RAND_bytes(IV, IVlen);
	memcpy(plain, plain_msg, strlen(plain_msg) + 1);

	/* Alloc and gen keys */
	ret = TEE_AllocateTransientObject(obj_type, key_size, &key);
	if (ret != TEE_SUCCESS) {
		printf("Fail: transient alloc key\n");
		goto err;
	}

	ret = TEE_GenerateKey(key, key_size, NULL, 0);
	if (ret != TEE_SUCCESS) {
		printf("Fail: gen key\n");
		goto err;
	}

	write_to_cipher = cipher_len;
	if (!warp_sym_enc(key, IV, IVlen, alg, plain, plain_len, cipher, &write_to_cipher))
		goto err;

	cipher_len = write_to_cipher;

	write_to_dec_plain = dec_plain_len;
	if (!warp_sym_dec(key, IV, IVlen, alg, cipher, cipher_len, dec_plain, &write_to_dec_plain))
		goto err;

	if (bcmp(dec_plain, plain, write_to_dec_plain)) {
		printf("Fail: can't dec from enc\n");
		goto err;
	}

err:
	TEE_FreeTransientObject(key);
	TEE_Free(plain);
	TEE_Free(IV);
	TEE_Free(cipher);
	TEE_Free(dec_plain);
}

static void AES_256_ctr_enc_and_dec()
{
	printf("  ####   AES_256_ctr_enc_and_dec   ####\n");

	TEE_Result ret = TEE_SUCCESS;
	size_t key_size = 256;
	TEE_ObjectHandle key = NULL;

	size_t plain_len = 20;
	size_t cipher_len = 20;
	size_t dec_plain_len = plain_len;
	size_t IVlen = key_size;

	void *plain = NULL;
	void *cipher = NULL;
	void *dec_plain = NULL;
	void *IV = NULL;

	size_t write_to_cipher = 0;
	size_t write_to_dec_plain = 0;

	IV = TEE_Malloc(IVlen, 0);
	plain = TEE_Malloc(plain_len, 0);
	cipher = TEE_Malloc(cipher_len, 0);
	dec_plain = TEE_Malloc(dec_plain_len, 0);
	if (!IV || !plain || !cipher || !dec_plain) {
		printf("Fail: IV || plain || cipher alloc || dec_plain\n");
		goto err;
	}
	RAND_bytes(IV, IVlen);
	RAND_bytes(plain, plain_len);

	/* Alloc and gen keys */
	ret = TEE_AllocateTransientObject(TEE_TYPE_AES, key_size, &key);
	if (ret != TEE_SUCCESS) {
		printf("Fail: transient alloc key\n");
		goto err;
	}

	ret = TEE_GenerateKey(key, key_size, NULL, 0);
	if (ret != TEE_SUCCESS) {
		printf("Fail: gen key\n");
		goto err;
	}

	write_to_cipher = cipher_len;
	if (!warp_sym_enc(key, IV, IVlen, TEE_ALG_AES_CTR, plain, plain_len, cipher, &write_to_cipher))
		goto err;

	cipher_len = write_to_cipher;

	write_to_dec_plain = dec_plain_len;
	if (!warp_sym_dec(key, IV, IVlen, TEE_ALG_AES_CTR, cipher, cipher_len, dec_plain, &write_to_dec_plain))
		goto err;

	if (bcmp(dec_plain, plain, write_to_dec_plain)) {
		printf("Fail: can't dec from enc\n");
		goto err;
	}

err:
	TEE_FreeTransientObject(key);
	TEE_Free(plain);
	TEE_Free(IV);
	TEE_Free(cipher);
	TEE_Free(dec_plain);
}

static void sha224_digest()
{
	printf("  ####   sha224_digest   ####\n");

	TEE_Result ret = TEE_SUCCESS;

	TEE_OperationHandle digest_handler = NULL;
	TEE_OperationHandle clone_digest_handler = NULL;
	TEE_OperationHandle cpy_digest_handler = NULL;

	void *rand_msg = NULL;
	void *clone_rand_msg = NULL;
	void *rand_msg_hash = NULL;
	void *clone_rand_msg_hash = NULL;
	void *cpy_hash_func = NULL;

	uint32_t rand_msg_len = 1000;
	uint32_t hash_len_bytes = 28;
	uint32_t rand_msg_hash_len = hash_len_bytes;
	uint32_t clone_rand_msg_hash_len = hash_len_bytes;
	uint32_t cpy_hash_func_len = hash_len_bytes;

	rand_msg = TEE_Malloc(rand_msg_len, 0);
	clone_rand_msg = TEE_Malloc(rand_msg_len, 0);
	rand_msg_hash = TEE_Malloc(hash_len_bytes, 0);
	clone_rand_msg_hash = TEE_Malloc(hash_len_bytes, 0);
	cpy_hash_func = TEE_Malloc(cpy_hash_func_len, 0);
	if (!rand_msg || !clone_rand_msg || !rand_msg_hash
	    || !clone_rand_msg_hash || !cpy_hash_func) {
		printf("Fail: buf alloc\n");
		goto err;
	}

	RAND_bytes(rand_msg, rand_msg_len);
	memcpy(clone_rand_msg, rand_msg, rand_msg_len);

	ret = TEE_AllocateOperation(&digest_handler, TEE_ALG_SHA224, TEE_MODE_DIGEST, 0);
	if (ret != TEE_SUCCESS) {
		printf("Fail: alloc digest handler\n");
		goto err;
	}

	ret = TEE_AllocateOperation(&clone_digest_handler, TEE_ALG_SHA224, TEE_MODE_DIGEST, 0);
	if (ret != TEE_SUCCESS) {
		printf("Fail: alloc clone digest handler\n");
		goto err;
	}

	ret = TEE_AllocateOperation(&cpy_digest_handler, TEE_ALG_SHA224, TEE_MODE_DIGEST, 0);
	if (ret != TEE_SUCCESS) {
		printf("Fail: alloc cpy digest handler\n");
		goto err;
	}

	TEE_DigestUpdate(digest_handler, rand_msg, rand_msg_len);
	TEE_DigestUpdate(digest_handler, rand_msg, rand_msg_len);

	TEE_DigestUpdate(clone_digest_handler, clone_rand_msg, rand_msg_len);
	TEE_DigestUpdate(clone_digest_handler, clone_rand_msg, rand_msg_len);

	TEE_CopyOperation(cpy_digest_handler, digest_handler);

	ret = TEE_DigestDoFinal(digest_handler, NULL, 0, rand_msg_hash, &rand_msg_hash_len);
	if (ret != TEE_SUCCESS) {
		printf("Fail: digest final\n");
		goto err;
	}

	ret = TEE_DigestDoFinal(clone_digest_handler, NULL, 0,
				clone_rand_msg_hash, &clone_rand_msg_hash_len);
	if (ret != TEE_SUCCESS) {
		printf("Fail: cpy digest final\n");
		goto err;
	}

	ret = TEE_DigestDoFinal(cpy_digest_handler, NULL, 0,
				cpy_hash_func, &cpy_hash_func_len);
	if (ret != TEE_SUCCESS) {
		printf("Fail: cpy digest final\n");
		goto err;
	}

	if (rand_msg_hash_len != clone_rand_msg_hash_len) {
		printf("Fail: hash len prob\n");
		goto err;
	}

	if (bcmp(rand_msg_hash, clone_rand_msg_hash, hash_len_bytes)) {
		printf("Fail: hash prob\n");
		goto err;
	}

	if (bcmp(rand_msg_hash, cpy_hash_func, hash_len_bytes)) {
		printf("Fail: cpy hash prob\n");
		goto err;
	}

err:
	TEE_FreeOperation(digest_handler);
	TEE_FreeOperation(clone_digest_handler);
	TEE_FreeOperation(cpy_digest_handler);
	TEE_Free(rand_msg);
	TEE_Free(clone_rand_msg);
	TEE_Free(rand_msg_hash);
	TEE_Free(clone_rand_msg_hash);
	TEE_Free(cpy_hash_func);
}

static void aes_256_cbc_enc_dec()
{
	printf("  ####   aes_256_cbc_enc_dec   ####\n");

	TEE_Result ret = TEE_SUCCESS;
	size_t key_size = 256;
	uint32_t obj_type = TEE_TYPE_AES;
	uint32_t alg = TEE_ALG_AES_CBC_NOPAD;
	TEE_ObjectHandle key = NULL;
	char *plain_msg = "TANEL";

	size_t plain_len = 128;
	size_t cipher_len = 128;
	size_t dec_plain_len = plain_len;
	size_t IVlen = key_size;

	void *plain = NULL;
	void *cipher = NULL;
	void *dec_plain = NULL;
	void *IV = NULL;

	size_t write_to_cipher = 0;
	size_t write_to_dec_plain = 0;

	IV = TEE_Malloc(IVlen, 0);
	plain = TEE_Malloc(plain_len, 0);
	cipher = TEE_Malloc(cipher_len, 0);
	dec_plain = TEE_Malloc(dec_plain_len, 0);
	if (!IV || !plain || !cipher || !dec_plain) {
		printf("Fail: IV || plain || cipher alloc || dec_plain\n");
		goto err;
	}
	RAND_bytes(IV, IVlen);
	memcpy(plain, plain_msg, strlen(plain_msg) + 1);

	/* Alloc and gen keys */
	ret = TEE_AllocateTransientObject(obj_type, key_size, &key);
	if (ret != TEE_SUCCESS) {
		printf("Fail: transient alloc key\n");
		goto err;
	}

	ret = TEE_GenerateKey(key, key_size, NULL, 0);
	if (ret != TEE_SUCCESS) {
		printf("Fail: gen key\n");
		goto err;
	}

	write_to_cipher = cipher_len;
	if (!warp_sym_enc(key, IV, IVlen, alg, plain, plain_len, cipher, &write_to_cipher))
		goto err;

	cipher_len = write_to_cipher;

	write_to_dec_plain = dec_plain_len;
	if (!warp_sym_dec(key, IV, IVlen, alg, cipher, cipher_len, dec_plain, &write_to_dec_plain))
		goto err;

	if (bcmp(dec_plain, plain, write_to_dec_plain)) {
		printf("Fail: can't dec from enc\n");
		goto err;
	}

err:
	TEE_FreeTransientObject(key);
	TEE_Free(plain);
	TEE_Free(IV);
	TEE_Free(cipher);
	TEE_Free(dec_plain);
}

static bool warp_RSA_enc(TEE_ObjectHandle key, uint32_t alg, TEE_Attribute* params,
			 uint32_t paramCount, void *plain, uint32_t plain_len,
			 void *cipher, uint32_t *cipher_len)
{
	TEE_Result ret = TEE_SUCCESS;
	TEE_OperationHandle enc_handle = NULL;
	TEE_ObjectInfo info;

	TEE_GetObjectInfo(key, &info);

	ret = TEE_AllocateOperation(&enc_handle, alg, TEE_MODE_ENCRYPT, info.maxObjectSize);
	if (ret != TEE_SUCCESS) {
		printf("Fail: alloc enc handle\n");
		goto err;
	}

	ret = TEE_SetOperationKey(enc_handle, key);
	if (ret != TEE_SUCCESS) {
		printf("Fail: set enc key\n");
		goto err;
	}

	ret = TEE_AsymmetricEncrypt(enc_handle, params, paramCount,
				    plain, plain_len, cipher, cipher_len);
	if (ret != TEE_SUCCESS) {
		printf("Fail: enc\n");
		goto err;
	}

	TEE_FreeOperation(enc_handle);
	return true;

err:
	TEE_FreeOperation(enc_handle);
	return false;
}

static bool warp_RSA_dec(TEE_ObjectHandle key, uint32_t alg, TEE_Attribute* params,
			 uint32_t paramCount, void *plain, uint32_t *plain_len,
			 void *cipher, uint32_t cipher_len)
{
	TEE_Result ret = TEE_SUCCESS;
	TEE_OperationHandle dec_handle = NULL;
	TEE_ObjectInfo info;

	TEE_GetObjectInfo(key, &info);

	ret = TEE_AllocateOperation(&dec_handle, alg, TEE_MODE_DECRYPT, info.maxObjectSize);
	if (ret != TEE_SUCCESS) {
		printf("Fail: alloc dec handle\n");
		goto err;
	}

	ret = TEE_SetOperationKey(dec_handle, key);
	if (ret != TEE_SUCCESS) {
		printf("Fail: set dec key\n");
		goto err;
	}

	ret = TEE_AsymmetricDecrypt(dec_handle, params, paramCount,
				    cipher, cipher_len, plain, plain_len);
	if (ret != TEE_SUCCESS) {
		printf("Fail: dec\n");
		goto err;
	}

	TEE_FreeOperation(dec_handle);
	return true;

err:
	TEE_FreeOperation(dec_handle);
	return false;
}

static void RSA_keypair_enc_dec()
{
	printf("  ####   RSA_keypair_enc_dec   ####\n");

	TEE_Result ret;
	TEE_ObjectHandle rsa_keypair = NULL;
	size_t key_size = 2048;
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1;
	char *plain_msg = "TANEL";

	uint32_t plain_len = 100;
	uint32_t cipher_len = 256;
	uint32_t dec_plain_len = 256;

	void *plain = NULL;
	void *cipher = NULL;
	void *dec_plain = NULL;

	plain = TEE_Malloc(plain_len, 0);
	cipher = TEE_Malloc(cipher_len, 0);
	dec_plain = TEE_Malloc(dec_plain_len, 0);
	if (!plain || !cipher || !dec_plain) {
		printf("Fail: plain || cipher alloc || dec_plain\n");
		goto err;
	}

	memcpy(plain, plain_msg, strlen(plain_msg) + 1);
	//RAND_bytes(plain, plain_len);

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &rsa_keypair);
	if (ret != TEE_SUCCESS) {
		printf("Fail: transient alloc\n");
		goto err;
	}

	ret = TEE_GenerateKey(rsa_keypair, key_size, NULL, 0);
	if (ret != TEE_SUCCESS) {
		printf("Fail: gen key\n");
		goto err;
	}

	if (!warp_RSA_enc(rsa_keypair, rsa_alg, NULL, 0,
			  plain, plain_len, cipher, &cipher_len))
		goto err;


	if (!warp_RSA_dec(rsa_keypair, rsa_alg, NULL, 0,
			  dec_plain, &dec_plain_len, (unsigned char *)cipher, cipher_len))
		goto err;

	if (bcmp(dec_plain, plain, plain_len)) {
		printf("Fail: can't dec from enc\n");
		goto err;
	}

err:
	TEE_FreeTransientObject(rsa_keypair);
	TEE_Free(plain);
	TEE_Free(dec_plain);
	TEE_Free(cipher);
}

static bool warp_RSA_sig(TEE_ObjectHandle key, uint32_t alg, TEE_Attribute* params,
			 uint32_t paramCount, void *dig, uint32_t dig_len,
			 void *sig, uint32_t *sig_len)
{
	TEE_Result ret = TEE_SUCCESS;
	TEE_OperationHandle sig_handle = NULL;
	TEE_ObjectInfo info;

	TEE_GetObjectInfo(key, &info);

	ret = TEE_AllocateOperation(&sig_handle, alg, TEE_MODE_SIGN, info.maxObjectSize);
	if (ret != TEE_SUCCESS) {
		printf("Fail: alloc enc handle\n");
		goto err;
	}

	ret = TEE_SetOperationKey(sig_handle, key);
	if (ret != TEE_SUCCESS) {
		printf("Fail: set enc key\n");
		goto err;
	}

	ret = TEE_AsymmetricSignDigest(sig_handle, params, paramCount,
				       dig, dig_len, sig, sig_len);
	if (ret != TEE_SUCCESS) {
		printf("Fail: sig\n");
		goto err;
	}

	TEE_FreeOperation(sig_handle);
	return true;

err:
	TEE_FreeOperation(sig_handle);
	return false;
}

static bool warp_RSA_ver(TEE_ObjectHandle key, uint32_t alg, TEE_Attribute* params,
			 uint32_t paramCount, void *dig, size_t dig_len,
			 void *sig, size_t sig_len)
{
	TEE_Result ret = TEE_SUCCESS;
	TEE_OperationHandle ver_handle = NULL;
	TEE_ObjectInfo info;

	TEE_GetObjectInfo(key, &info);

	ret = TEE_AllocateOperation(&ver_handle, alg, TEE_MODE_VERIFY, info.maxObjectSize);
	if (ret != TEE_SUCCESS) {
		printf("Fail: alloc enc handle\n");
		goto err;
	}

	ret = TEE_SetOperationKey(ver_handle, key);
	if (ret != TEE_SUCCESS) {
		printf("Fail: set enc key\n");
		goto err;
	}

	ret = TEE_AsymmetricVerifyDigest(ver_handle, params, paramCount,
					 dig, dig_len, sig, sig_len);
	if (ret != TEE_SUCCESS) {
		printf("Fail: ver\n");
		goto err;
	}

	TEE_FreeOperation(ver_handle);
	return true;

err:
	TEE_FreeOperation(ver_handle);
	return false;
}

static void RSA_sig_and_ver()
{
	printf("  ####   RSA_sig_and_ver   ####\n");

	TEE_Result ret;
	TEE_ObjectHandle rsa_keypair = NULL;
	size_t key_size = 512;
	uint32_t rsa_alg = TEE_ALG_RSASSA_PKCS1_V1_5_SHA1;
	char *dig_msg = "TANEL"; /* dig msg :) */

	uint32_t dig_len = 20;
	uint32_t sig_len = 64;

	void *dig = NULL;
	void *sig = NULL;

	dig = TEE_Malloc(dig_len, 0);
	sig = TEE_Malloc(sig_len, 0);
	if (!dig || !sig) {
		printf("Fail: dig || sig alloc\n");
		goto err;
	}

	memcpy(dig, dig_msg, strlen(dig_msg) + 1);

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &rsa_keypair);
	if (ret != TEE_SUCCESS) {
		printf("Fail: transient alloc\n");
		goto err;
	}

	ret = TEE_GenerateKey(rsa_keypair, key_size, NULL, 0);
	if (ret != TEE_SUCCESS) {
		printf("Fail: gen key\n");
		goto err;
	}

	if (!warp_RSA_sig(rsa_keypair, rsa_alg, NULL, 0,
			  dig, dig_len, sig, &sig_len))
		goto err;

	if (!warp_RSA_ver(rsa_keypair, rsa_alg, NULL, 0,
			  dig, dig_len, sig, sig_len))
		goto err;

err:
	TEE_FreeTransientObject(rsa_keypair);
	TEE_Free(dig);
	TEE_Free(sig);
}

static void HMAC_computation()
{
	printf("  ####   HMAC_computation   ####\n");

	TEE_Result ret;
	TEE_ObjectHandle hmac_key = NULL;
	TEE_OperationHandle hmac_handle = NULL;
	TEE_OperationHandle hmac_handle2 = NULL;
	size_t key_size = 256;
	uint32_t alg = TEE_ALG_HMAC_SHA512;
	uint32_t alg2 = TEE_ALG_HMAC_SHA512;
	char *seed_msg = "TANEL";
	char *seed_msg2 = "TANEL";

	u_int32_t mac_len = 64;
	u_int32_t mac_len2 = 64;
	size_t msg_len = 100;
	size_t msg_len2 = 100;

	void *mac = NULL;
	void *mac2 = NULL;
	void *msg = NULL;
	void *msg2 = NULL;

	mac = TEE_Malloc(mac_len, 0);
	mac2 = TEE_Malloc(mac_len2, 0);
	msg = TEE_Malloc(msg_len, 0);
	msg2 = TEE_Malloc(msg_len2, 0);
	if (!mac || !msg || !mac2 || !msg2) {
		printf("Fail: mac || msg alloc || mac2\n");
		goto err;
	}

	memcpy(msg, seed_msg, strlen(seed_msg) + 1);
	memcpy(msg2, seed_msg2, strlen(seed_msg2) + 1);

	ret = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, key_size, &hmac_key);
	if (ret != TEE_SUCCESS) {
		printf("Fail: transient alloc\n");
		goto err;
	}

	ret = TEE_GenerateKey(hmac_key, key_size, NULL, 0);
	if (ret != TEE_SUCCESS) {
		printf("Fail: gen key\n");
		goto err;
	}

	ret = TEE_AllocateOperation(&hmac_handle, alg, TEE_MODE_MAC, key_size);
	if (ret != TEE_SUCCESS) {
		printf("Fail: alloc hmac handle\n");
		goto err;
	}

	ret = TEE_AllocateOperation(&hmac_handle2, alg2, TEE_MODE_MAC, key_size);
	if (ret != TEE_SUCCESS) {
		printf("Fail: alloc hmac handle\n");
		goto err;
	}

	ret = TEE_SetOperationKey(hmac_handle, hmac_key);
	if (ret != TEE_SUCCESS) {
		printf("Fail: set hmac key\n");
		goto err;
	}

	ret = TEE_SetOperationKey(hmac_handle2, hmac_key);
	if (ret != TEE_SUCCESS) {
		printf("Fail: set hmac key\n");
		goto err;
	}

	TEE_MACInit(hmac_handle, NULL, 0);
	TEE_MACUpdate(hmac_handle, msg, msg_len);
	ret = TEE_MACComputeFinal(hmac_handle, NULL, 0, mac, &mac_len);
	if (ret != TEE_SUCCESS) {
		printf("Fail: shmac fin\n");
		goto err;
	}

	TEE_MACInit(hmac_handle2, NULL, 0);
	TEE_MACUpdate(hmac_handle2, msg2, msg_len2);
	ret = TEE_MACComputeFinal(hmac_handle2, NULL, 0, mac2, &mac_len2);
	if (ret != TEE_SUCCESS) {
		printf("Fail: shmac fin\n");
		goto err;
	}

	if (bcmp(mac, mac2, mac_len)) {
		printf("Fail: hmac cmp\n");
		goto err;
	}

err:
	TEE_FreeTransientObject(hmac_key);
	TEE_FreeOperation(hmac_handle);
	TEE_FreeOperation(hmac_handle2);
	TEE_Free(mac);
	TEE_Free(mac2);
	TEE_Free(msg);
	TEE_Free(msg2);
}

static void CMAC_computation()
{
	printf("  ####   CMAC_computation   ####\n");

	TEE_Result ret;
	TEE_ObjectHandle hmac_key = NULL;
	TEE_OperationHandle hmac_handle = NULL;
	TEE_OperationHandle hmac_handle2 = NULL;
	size_t key_size = 256;
	uint32_t alg = TEE_ALG_AES_CMAC;
	uint32_t alg2 = TEE_ALG_AES_CMAC;
	char *seed_msg = "TANEL";
	char *seed_msg2 = "TANEL";

	u_int32_t mac_len = 64;
	u_int32_t mac_len2 = 64;
	size_t msg_len = 100;
	size_t msg_len2 = 100;

	void *mac = NULL;
	void *mac2 = NULL;
	void *msg = NULL;
	void *msg2 = NULL;

	mac = TEE_Malloc(mac_len, 0);
	mac2 = TEE_Malloc(mac_len2, 0);
	msg = TEE_Malloc(msg_len, 0);
	msg2 = TEE_Malloc(msg_len2, 0);
	if (!mac || !msg || !mac2 || !msg2) {
		printf("Fail: mac || msg alloc || mac2\n");
		goto err;
	}

	memcpy(msg, seed_msg, strlen(seed_msg) + 1);
	memcpy(msg2, seed_msg2, strlen(seed_msg2) + 1);

	ret = TEE_AllocateTransientObject(TEE_TYPE_AES, key_size, &hmac_key);
	if (ret != TEE_SUCCESS) {
		printf("Fail: transient alloc\n");
		goto err;
	}

	ret = TEE_GenerateKey(hmac_key, key_size, NULL, 0);
	if (ret != TEE_SUCCESS) {
		printf("Fail: gen key\n");
		goto err;
	}

	ret = TEE_AllocateOperation(&hmac_handle, alg, TEE_MODE_MAC, key_size);
	if (ret != TEE_SUCCESS) {
		printf("Fail: alloc cmac handle\n");
		goto err;
	}

	ret = TEE_AllocateOperation(&hmac_handle2, alg2, TEE_MODE_MAC, key_size);
	if (ret != TEE_SUCCESS) {
		printf("Fail: alloc cmac handle\n");
		goto err;
	}

	ret = TEE_SetOperationKey(hmac_handle, hmac_key);
	if (ret != TEE_SUCCESS) {
		printf("Fail: set cmac key\n");
		goto err;
	}

	ret = TEE_SetOperationKey(hmac_handle2, hmac_key);
	if (ret != TEE_SUCCESS) {
		printf("Fail: set cmac key\n");
		goto err;
	}

	TEE_MACInit(hmac_handle, NULL, 0);
	TEE_MACUpdate(hmac_handle, msg, msg_len);
	ret = TEE_MACComputeFinal(hmac_handle, NULL, 0, mac, &mac_len);
	if (ret != TEE_SUCCESS) {
		printf("Fail: cmac fin\n");
		goto err;
	}

	TEE_MACInit(hmac_handle2, NULL, 0);
	TEE_MACUpdate(hmac_handle2, msg2, msg_len2);
	ret = TEE_MACComputeFinal(hmac_handle2, NULL, 0, mac2, &mac_len2);
	if (ret != TEE_SUCCESS) {
		printf("Fail: cmac fin\n");
		goto err;
	}

	if (bcmp(mac, mac2, mac_len)) {
		printf("Fail: cmac cmp\n");
		goto err;
	}

err:
	TEE_FreeOperation(hmac_handle);
	TEE_FreeOperation(hmac_handle2);
	TEE_FreeTransientObject(hmac_key);
	TEE_Free(mac);
	TEE_Free(mac2);
	TEE_Free(msg);
	TEE_Free(msg2);
}

static void DH_computaion()
{
	printf("  ####   DH_computaion   ####\n");

	TEE_Result ret;
	TEE_ObjectHandle dh_key = NULL;
	TEE_ObjectHandle dh_key2 = NULL;
	TEE_OperationHandle dh_han = NULL;
	TEE_OperationHandle dh_han2 = NULL;
	TEE_ObjectHandle der_sec = NULL;
	TEE_ObjectHandle der_sec2 = NULL;
	TEE_Attribute *params;
	TEE_Attribute dh_pub;
	TEE_Attribute dh_pub2;
	TEE_Attribute gen_sec;
	BIGNUM *bn_p = NULL;
	BIGNUM *bn_q = NULL;
	uint32_t alg = TEE_ALG_DH_DERIVE_SHARED_SECRET;
	void *derived_sec_buf = NULL;
	void *derived_sec_buf2 = NULL;

	size_t param_count = 2;
	size_t key_size = 256;
	size_t pub_max_size = 100;
	size_t p_len = 60;
	size_t q_len = 10;
	size_t shared_sec_len = 4000;
	size_t derived_sec_len = 40;
	size_t derived_sec_len2 = derived_sec_len;

	derived_sec_buf = TEE_Malloc(derived_sec_len, 0);
	derived_sec_buf2 = TEE_Malloc(derived_sec_len2, 0);
	if (!derived_sec_buf || !derived_sec_buf2)
		goto err;

	//Pub vals
	dh_pub.content.ref.buffer = TEE_Malloc(pub_max_size, 0);
	dh_pub2.content.ref.buffer = TEE_Malloc(pub_max_size, 0);
	if (!dh_pub.content.ref.buffer || !dh_pub2.content.ref.buffer) {
		printf("Fail: malloc dh pub || dh_pub2\n");
		goto err;
	}
	dh_pub.content.ref.length = pub_max_size;
	dh_pub2.content.ref.length = pub_max_size;
	dh_pub.attributeID = TEE_ATTR_DH_PUBLIC_VALUE;
	dh_pub2.attributeID = TEE_ATTR_DH_PUBLIC_VALUE;

	//Gen sec
	gen_sec.attributeID = TEE_ATTR_SECRET_VALUE;
	gen_sec.content.ref.buffer = TEE_Malloc(shared_sec_len, 0);
	if (!gen_sec.content.ref.buffer) {
		printf("Fail: malloc dh pub || dh_pub2\n");
		goto err;
	}
	gen_sec.content.ref.length = shared_sec_len;

	params = TEE_Malloc(param_count * sizeof(TEE_Attribute), 0);
	if (params == NULL)
		goto err;

	// p
	bn_p = BN_new();
	if (!bn_p)
		goto err;
	if (!BN_generate_prime_ex(bn_p, (p_len*8), 1, NULL, NULL, NULL))
		goto err;
	params[0].attributeID = TEE_ATTR_DH_BASE;
	params[0].content.ref.buffer = TEE_Malloc(p_len, 0);
	if (params[0].content.ref.buffer == NULL)
		goto err;
	if (!BN_bn2bin(bn_p, params[0].content.ref.buffer))
		goto err;
	params[0].content.ref.length = BN_num_bytes(bn_p);

	// q
	bn_q = BN_new();
	if (!bn_q)
		goto err;
	if (!BN_generate_prime_ex(bn_q, (q_len*8), 1, NULL, NULL, NULL))
		goto err;
	params[1].attributeID = TEE_ATTR_DH_PRIME;
	params[1].content.ref.buffer = TEE_Malloc(q_len, 0);
	if (params[1].content.ref.buffer == NULL)
		goto err;
	if (!BN_bn2bin(bn_q, params[1].content.ref.buffer))
		goto err;
	params[1].content.ref.length = q_len;

	ret = TEE_AllocateTransientObject(TEE_TYPE_DH_KEYPAIR, key_size, &dh_key);
	if (ret != TEE_SUCCESS) {
		printf("Fail: transient alloc\n");
		goto err;
	}

	ret = TEE_AllocateTransientObject(TEE_TYPE_DH_KEYPAIR, key_size, &dh_key2);
	if (ret != TEE_SUCCESS) {
		printf("Fail: transient alloc\n");
		goto err;
	}

	ret = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET, shared_sec_len, &der_sec);
	if (ret != TEE_SUCCESS) {
		printf("Fail: transient alloc\n");
		goto err;
	}

	ret = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET, shared_sec_len, &der_sec2);
	if (ret != TEE_SUCCESS) {
		printf("Fail: transient alloc\n");
		goto err;
	}

	ret = TEE_PopulateTransientObject(der_sec, &gen_sec, 1);
	if (ret != TEE_SUCCESS) {
		printf("Fail: Popu der_sec\n");
		goto err;
	}

	ret = TEE_PopulateTransientObject(der_sec2, &gen_sec, 1);
	if (ret != TEE_SUCCESS) {
		printf("Fail: Popu der_sec2\n");
		goto err;
	}

	ret = TEE_GenerateKey(dh_key, key_size, params, param_count);
	if (ret != TEE_SUCCESS) {
		printf("Fail: gen key\n");
		goto err;
	}

	ret = TEE_GenerateKey(dh_key2, key_size, params, param_count);
	if (ret != TEE_SUCCESS) {
		printf("Fail: gen key\n");
		goto err;
	}

	ret = TEE_GetObjectBufferAttribute(dh_key, TEE_ATTR_DH_PUBLIC_VALUE,
					   dh_pub.content.ref.buffer, &dh_pub.content.ref.length);
	if (ret != TEE_SUCCESS) {
		printf("Fail: extract pub\n");
		goto err;
	}

	ret = TEE_GetObjectBufferAttribute(dh_key2, TEE_ATTR_DH_PUBLIC_VALUE,
					   dh_pub2.content.ref.buffer, &dh_pub2.content.ref.length);
	if (ret != TEE_SUCCESS) {
		printf("Fail: extract pub2\n");
		goto err;
	}

	ret = TEE_AllocateOperation(&dh_han, alg, TEE_MODE_DERIVE, key_size);
	if (ret != TEE_SUCCESS) {
		printf("Fail: alloc op handle\n");
		goto err;
	}

	ret = TEE_AllocateOperation(&dh_han2, alg, TEE_MODE_DERIVE, key_size);
	if (ret != TEE_SUCCESS) {
		printf("Fail: alloc op handle\n");
		goto err;
	}

	ret = TEE_SetOperationKey(dh_han, dh_key);
	if (ret != TEE_SUCCESS) {
		printf("Fail: set cmac key\n");
		goto err;
	}

	ret = TEE_SetOperationKey(dh_han2, dh_key2);
	if (ret != TEE_SUCCESS) {
		printf("Fail: set cmac key\n");
		goto err;
	}

	TEE_DeriveKey(dh_han, &dh_pub2, 1, der_sec);
	TEE_DeriveKey(dh_han2, &dh_pub, 1, der_sec2);

	ret = TEE_GetObjectBufferAttribute(der_sec, TEE_ATTR_SECRET_VALUE,
					   derived_sec_buf, &derived_sec_len);
	if (ret != TEE_SUCCESS) {
		printf("Fail: extract sec\n");
		goto err;
	}


	ret = TEE_GetObjectBufferAttribute(der_sec2, TEE_ATTR_SECRET_VALUE,
					   derived_sec_buf2, &derived_sec_len2);
	if (ret != TEE_SUCCESS) {
		printf("Fail: extract sec2\n");
		goto err;
	}

	if (derived_sec_len != derived_sec_len2) {
		printf("Fail: Sec len do not match\n");
		goto err;
	}

	if (bcmp(derived_sec_buf, derived_sec_buf2, derived_sec_len)) {
		printf("Fail: Secs not match\n");
		goto err;
	}

err:
	TEE_FreeOperation(dh_han);
	TEE_FreeOperation(dh_han2);
	TEE_FreeTransientObject(dh_key);
	TEE_FreeTransientObject(dh_key2);
	TEE_FreeTransientObject(der_sec);
	TEE_FreeTransientObject(der_sec2);
	free_attr(params, param_count);
	TEE_Free(params);
	TEE_Free(dh_pub.content.ref.buffer);
	TEE_Free(dh_pub2.content.ref.buffer);
	BN_free(bn_p);
	BN_free(bn_q);
	TEE_Free(gen_sec.content.ref.buffer);
	TEE_Free(derived_sec_buf);
	TEE_Free(derived_sec_buf2);
}

static void dup_rsa_key()
{
	printf("  ####   dup_rsa_key   ####\n");

	TEE_Result ret;
	TEE_ObjectHandle key = NULL;
	uint32_t key_size = 512;
	TEE_OperationHandle src_op = NULL;
	TEE_OperationHandle dst_op = NULL;

	char *plain_msg = "TANEL";

	uint32_t plain_len = key_size/8;
	uint32_t cipher_len = key_size/8;
	uint32_t cpy_cipher_len = cipher_len;

	void *plain = NULL;
	void *cipher = NULL;
	void *cpy_cipher = NULL;

	plain = TEE_Malloc(plain_len, 0);
	cipher = TEE_Malloc(cipher_len, 0);
	cpy_cipher = TEE_Malloc(cpy_cipher_len, 0);
	if (!plain || !cipher || !cpy_cipher) {
		printf("Fail: plain || cipher || cpy_ciper alloc \n");
		goto err;
	}

	memcpy(plain, plain_msg, strlen(plain_msg) + 1);

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &key);
	if (ret != TEE_SUCCESS) {
		printf("Fail: transient alloc\n");
		goto err;
	}

	ret = TEE_GenerateKey(key, key_size, NULL, 0);
	if (ret != TEE_SUCCESS) {
		printf("Fail: gen key\n");
		goto err;
	}

	ret = TEE_AllocateOperation(&src_op, TEE_ALG_RSA_NOPAD, TEE_MODE_ENCRYPT, key_size);
	if (ret != TEE_SUCCESS) {
		printf("Fail: alloc src handle\n");
		goto err;
	}

	ret = TEE_AllocateOperation(&dst_op, TEE_ALG_RSA_NOPAD, TEE_MODE_ENCRYPT, key_size);
	if (ret != TEE_SUCCESS) {
		printf("Fail: alloc dst handle\n");
		goto err;
	}

	ret = TEE_SetOperationKey(src_op, key);
	if (ret != TEE_SUCCESS) {
		printf("Fail: set op key\n");
		goto err;
	}

	TEE_CopyOperation(dst_op, src_op);

	ret = TEE_AsymmetricEncrypt(dst_op, NULL, 0,
				    plain, plain_len, cipher, &cipher_len);
	if (ret != TEE_SUCCESS) {
		printf("Fail: enc\n");
		goto err;
	}

	ret = TEE_AsymmetricEncrypt(src_op, NULL, 0,
				    plain, plain_len, cpy_cipher, &cpy_cipher_len);
	if (ret != TEE_SUCCESS) {
		printf("Fail: enc cpy\n");
		goto err;
	}

	if (cpy_cipher_len != cipher_len) {
		printf("Fail: Len not same\n");
		goto err;
	}

	if (bcmp(cpy_cipher, cipher, cipher_len)) {
		printf("Fail: Cip buf not match\n");
		goto err;
	}

err:
	TEE_FreeTransientObject(key);
	TEE_FreeOperation(dst_op);
	TEE_FreeOperation(src_op);
	TEE_Free(cpy_cipher);
	TEE_Free(cipher);
	TEE_Free(plain);
}

int main()
{
	openlog(NULL, 0, 0);

	printf(" #!# Start test #!#\n");

	des3_cbc_enc_dec();
	aes_256_cbc_enc_dec();
	AES_256_ctr_enc_and_dec();
	AES_256_xts_enc_and_dec();
	set_RSA_key_to_operation();
	sha224_digest();
	RSA_keypair_enc_dec();
	RSA_sig_and_ver();
	HMAC_computation();
	CMAC_computation();
	DH_computaion();
	dup_rsa_key();

	printf(" #!# Test has reached end! #!#\n");

	closelog();
	return 0;
}

