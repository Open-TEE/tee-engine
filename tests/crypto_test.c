#include <openssl/rand.h>

#include <stdio.h>
#include <syslog.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Extreme simply smoke tests. If something than function name is printed -> FAIL */

/* NOTICE
 * Change our path */
#include "/home/dettenbo/opentee/emulator/include/tee_internal_api.h"

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

struct persistant_object_info {
	char obj_id[TEE_OBJECT_ID_MAX_LEN + 1];
	size_t obj_id_len;
	FILE *object_file;
	long data_begin;
	long data_size;
	long data_position;
};

struct __TEE_ObjectHandle {
	struct persistant_object_info per_object;
	TEE_ObjectInfo objectInfo;
	TEE_Attribute *attrs;
	uint32_t attrs_count;
	uint32_t maxObjSizeBytes;
};

struct key {
	RSA *rsa_key;
	DSA *dsa_key;
	DH *dh_key;
	void *sym_key;
	uint32_t sym_key_len;
	EVP_CIPHER_CTX *ctx;
};

struct __TEE_OperationHandle{
	TEE_OperationInfo operation_info;
	struct key key;
};

/* pri_obj_attr - function is only for testing. Before merge, remove! */
static void pri_obj_attr(TEE_ObjectHandle object)
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

/* pri_and_cmp_attr - function is only for testing. Before merge, remove! */
static void pri_and_cmp_attr(TEE_ObjectHandle obj1, TEE_ObjectHandle obj2)
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

static void pri_obj_data(TEE_ObjectHandle object)
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

static void pri_obj_info(TEE_ObjectInfo info)
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

static void gen_rand_per_data_obj(TEE_ObjectHandle *gen_obj, size_t data_len)
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

static void gen_RSA_per_obj_with_data(TEE_ObjectHandle *gen_obj, size_t data_len)
{
	TEE_Result ret;
	TEE_ObjectHandle handler;
	size_t key_size = 512;
	void *ID = NULL;
	size_t ID_len = 30;
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

static void AES_256_ctr_enc_and_dec()
{
	printf("  ####   AES_256_ctr_enc_and_dec   ####\n");

	TEE_Result ret;
	TEE_ObjectHandle key_handler = NULL;
	size_t key_size = 256;
	TEE_OperationHandle enc_handle = NULL;
	TEE_OperationHandle dec_handle = NULL;
	void *plain = NULL;
	size_t plain_len = 100;
	void *cipher = NULL;
	size_t cipher_len = key_size;
	void *IV = NULL;
	size_t IVlen = key_size;
	size_t write_bytes = 0;

	IV = TEE_Malloc(IVlen, 0);
	plain = TEE_Malloc(plain_len, 0);
	cipher = TEE_Malloc(cipher_len, 0);
	if (!IV || !plain || !cipher) {
		printf("Fail: IV || plain || cipher alloc\n");
		goto err;
	}
	RAND_bytes(IV, IVlen);
	RAND_bytes(plain, plain_len);

	printf("plain: \n");
	pri_void_buf(plain, plain_len);


	ret = TEE_AllocateTransientObject(TEE_TYPE_AES, key_size, &key_handler);
	if (ret != TEE_SUCCESS) {
		printf("Fail: transient alloc\n");
		goto err;
	}

	ret = TEE_GenerateKey(key_handler, key_size, NULL, 0);
	if (ret != TEE_SUCCESS) {
		printf("Fail: gen key\n");
		goto err;
	}

	ret = TEE_AllocateOperation(&enc_handle, TEE_ALG_AES_CTR, TEE_MODE_ENCRYPT, key_size);
	if (ret != TEE_SUCCESS) {
		printf("Fail: alloc enc handle\n");
		goto err;
	}

	ret = TEE_AllocateOperation(&dec_handle, TEE_ALG_AES_CTR, TEE_MODE_DECRYPT, key_size);
	if (ret != TEE_SUCCESS) {
		printf("Fail: alloc dec handle\n");
		goto err;
	}

	ret = TEE_SetOperationKey(enc_handle, key_handler);
	if (ret != TEE_SUCCESS) {
		printf("Fail: set enc key\n");
		goto err;
	}

	ret = TEE_SetOperationKey(dec_handle, key_handler);
	if (ret != TEE_SUCCESS) {
		printf("Fail: set dec key\n");
		goto err;
	}

	TEE_CipherInit(enc_handle, NULL, 0);
	TEE_CipherInit(dec_handle, NULL, 0);

	ret = TEE_CipherUpdate(enc_handle, plain, plain_len, cipher, &write_bytes);
	if (ret != TEE_SUCCESS) {
		printf("Fail: update enc\n");
		goto err;
	}

	ret = TEE_CipherDoFinal(enc_handle, NULL, 0,
				(unsigned char *)cipher + write_bytes, &write_bytes);
	if (ret != TEE_SUCCESS) {
		printf("Fail: update enc\n");
		goto err;
	}

	printf("cipher: \n");
	pri_void_buf(cipher, cipher_len);
	memset(plain, 0, plain_len);
	printf("plain zero: \n");
	pri_void_buf(plain, plain_len);

	ret = TEE_CipherUpdate(dec_handle, cipher, cipher_len, plain, &write_bytes);
	if (ret != TEE_SUCCESS) {
		printf("Fail: update enc\n");
		goto err;
	}

	ret = TEE_CipherDoFinal(enc_handle, NULL, 0,
				(unsigned char *)plain + write_bytes, &write_bytes);
	if (ret != TEE_SUCCESS) {
		printf("Fail: update enc\n");
		goto err;
	}

	printf("dec plain: \n");
	pri_void_buf(plain, plain_len);

err:
	TEE_FreeTransientObject(key_handler);
	TEE_FreeOperation(enc_handle);
	TEE_FreeOperation(dec_handle);
}

static void set_RSA_key_to_operation()
{
	printf("  ####   set_RSA_key_to_operation   ####\n");

	TEE_Result ret;
	TEE_ObjectHandle key = NULL;
	size_t key_size = 512;
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
	size_t plain_len = 100;
	void *cipher = NULL;
	size_t cipher_len = key_size + 1; /* +1 if you like add \n */
	void *IV = NULL;
	size_t IVlen = key_size;
	size_t write_bytes = 0;
	size_t total_write_bytes = 0;

	IV = TEE_Malloc(IVlen, 0);
	plain = TEE_Malloc(plain_len, 0);
	cipher = TEE_Malloc(cipher_len, 0);
	if (!IV || !plain || !cipher) {
		printf("Fail: IV || plain || cipher alloc\n");
		goto err;
	}
	RAND_bytes(IV, IVlen);
	RAND_bytes(plain, plain_len);

	printf("plain: \n");
	pri_void_buf(plain, plain_len);

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
	ret = TEE_CipherUpdate(enc_handle, plain, plain_len, cipher, &write_bytes);
	if (ret != TEE_SUCCESS) {
		printf("Fail: update enc\n");
		goto err;
	}

	total_write_bytes += write_bytes;

	ret = TEE_CipherDoFinal(enc_handle, NULL, 0,
				(unsigned char *)cipher + write_bytes, &write_bytes);
	if (ret != TEE_SUCCESS) {
		printf("Fail: update enc\n");
		goto err;
	}

	total_write_bytes += write_bytes;
	printf("cipher: \n");
	pri_void_buf(cipher, cipher_len);
	memset(plain, 0, plain_len);

	/* Encrypt */
	ret = TEE_CipherUpdate(dec_handle, cipher, total_write_bytes, plain, &write_bytes);
	if (ret != TEE_SUCCESS) {
		printf("Fail: update enc\n");
		goto err;
	}

	ret = TEE_CipherDoFinal(enc_handle, NULL, 0,
				(unsigned char *)plain + write_bytes, &write_bytes);
	if (ret != TEE_SUCCESS) {
		printf("Fail: update enc\n");
		goto err;
	}

	/* free stuff */

	printf("dec plain: \n");
	pri_void_buf(plain, plain_len);

err:
	return;
	/*
	TEE_FreeTransientObject(key1);
	TEE_FreeTransientObject(key2);
	TEE_FreeOperation(enc_handle);
	TEE_FreeOperation(dec_handle);
	TEE_Free(IV);
	TEE_Free(cipher);
	TEE_Free(plain);
*/
}

int main()
{
	openlog(NULL, 0, 0);

	printf(" #!# Start test #!#\n");

	//set_RSA_key_to_operation();
	//AES_256_ctr_enc_and_dec();
	AES_256_xts_enc_and_dec();

	printf(" #!# Test has reached end! #!#\n");

	closelog();
	return 0;
}

