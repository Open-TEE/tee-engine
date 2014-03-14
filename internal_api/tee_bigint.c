/*****************************************************************************
** Copyright (C) 2014 Intel Corporation.                                    **
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

#include "tee_bigint.h"
#include "tee_memory.h"

#include <openssl/bn.h>

#include <string.h>

void TEE_BigIntInit(TEE_BigInt *bigInt, size_t len) {
	if (bigInt == NULL)
		return;

	if (len == 0)
		return;

        // Fill the memory area with zeros
	memset(bigInt, 0, len * sizeof(uint32_t));

	struct TEE_BigInt_InternalHeader *header =
		(struct TEE_BigInt_InternalHeader *) bigInt;

	// Store length to header in the beginning of the array
	header->length =
		len - (sizeof(struct TEE_BigInt_InternalHeader) /
			sizeof(uint32_t));
}

static int32_t BigIntToBN(BIGNUM *dest, TEE_BigInt *src) {
	struct TEE_BigInt_InternalHeader *header =
		(struct TEE_BigInt_InternalHeader *) src;

        unsigned char *data =
		&((unsigned char*) src)
		[sizeof(struct TEE_BigInt_InternalHeader)];

	BIGNUM *ret = BN_bin2bn(data, header->length, dest);
	if (ret == NULL)
	{
		printf("BigInt -> BN conversion failed");
		return -1;
	}

	BN_set_negative(dest, header->neg);

	return 0;
}

static int32_t BNToBigInt(TEE_BigInt *dest, const BIGNUM *src) {
	struct TEE_BigInt_InternalHeader *header =
		(struct TEE_BigInt_InternalHeader *) dest;

	int representation_length =
		BN_num_bytes(src) / sizeof(uint32_t);

	// Check if representation fits in given TEE_BigInt
	if (header->length < (unsigned int)representation_length)
	{
		printf("Does not fit %i < %i\n",
				header->length,
				(unsigned int)representation_length);
		return -1;
	}

	header->neg = BN_is_negative(src) ? 1 : 0;

        unsigned char *data =
		&((unsigned char*) dest)
		[sizeof(struct TEE_BigInt_InternalHeader)];

	BN_bn2bin(src, data);

	return 0;
}

TEE_Result TEE_BigIntConvertFromOctetString(
	TEE_BigInt *dest,
	uint8_t *buffer,
	size_t bufferLen,
	int32_t sign) {

	TEE_Result ret = TEE_ERROR_OVERFLOW;

	int8_t *str = TEE_Malloc(bufferLen + 1, 0);
	if (str == NULL)
		goto err1;

	TEE_MemMove(str, buffer, bufferLen);
	str[bufferLen] = '\0';

	BIGNUM *num = BN_new();
	if (!num)
		goto err1;

	if (!BN_hex2bn(&num, (const char *)str))
		goto err2;

	if (sign != 0)
		BN_set_negative(num, 1);

	if (BNToBigInt(dest, num))
		goto err2;

	ret = TEE_SUCCESS;

err2:
	BN_clear_free(num);
err1:
	TEE_Free(str);

	return ret;
}

TEE_Result TEE_BigIntConvertToOctetString(
	void *buffer,
	size_t bufferLen,
	TEE_BigInt *bigInt) {

	TEE_Result ret = TEE_ERROR_SHORT_BUFFER;

	BIGNUM *num = BN_new();
	if (!num)
		goto err1;

	if (BigIntToBN(num, bigInt))
		goto err2;

	char *str = BN_bn2hex(num);
	if (!str)
		goto err2;

	size_t length_of_str = strlen(str);
	if (bufferLen < length_of_str)
		goto err3;

	strncpy(buffer, str, bufferLen);
	((char *)buffer)[length_of_str] = '\0';

	ret = TEE_SUCCESS;

err3:
	OPENSSL_free(str);
err2:
	BN_clear_free(num);
err1:
	return ret;
}

void TEE_BigIntConvertFromS32(
	TEE_BigInt *dest,
	int32_t shortVal) {

	//uint32_t val = htonl((uint32_t)shortVal);
	uint32_t val = shortVal;

	BIGNUM *bn_dest = BN_new();

	bn_dest = BN_bin2bn((uint8_t *)(&val), sizeof(uint32_t), bn_dest);

	if (BNToBigInt(dest, bn_dest))
	        goto error;

error:
	BN_clear_free(bn_dest);
}

void TEE_BigIntConvertToS32(
	int32_t *dest,
	TEE_BigInt *src) {

	BIGNUM *bn_src = BN_new();

	if (!bn_src)
		goto error;

	if (BigIntToBN(bn_src, src))
		goto error;

	size_t representation_length = BN_num_bytes(bn_src);

	if (representation_length == 0)
		*dest = 0;
	else if (representation_length > 0 && representation_length <= 4)
		BN_bn2bin(bn_src, (uint8_t *)dest);
	else
		printf("Too big representation");

error:
	BN_clear_free(bn_src);
}

int32_t TEE_BigIntCmp(TEE_BigInt *op1, TEE_BigInt *op2) {
	BIGNUM *bn_op1 = BN_new();
	BIGNUM *bn_op2 = BN_new();

	int32_t ret = -200;

	if (!bn_op1 || !bn_op2)
		goto error;

	if (BigIntToBN(bn_op1, op1))
		goto error;

	if (BigIntToBN(bn_op2, op2))
		goto error;

	ret = BN_cmp(bn_op1, bn_op2);

error:
	BN_clear_free(bn_op1);
	BN_clear_free(bn_op2);

	return ret;
}

void TEE_BigIntShiftRight(
	TEE_BigInt *dest,
	TEE_BigInt *op,
	size_t bits)
{
	BIGNUM *result = BN_new();
	BIGNUM *bn_op = BN_new();

	if (!result || !bn_op)
		goto error;

	if (BigIntToBN(bn_op, op))
		goto error;

	if (!BN_rshift(result, bn_op, bits))
		goto error;

	if (BNToBigInt(dest, result))
	        goto error;

error:
	BN_clear_free(result);
	BN_clear_free(bn_op);
}

bool TEE_BigIntGetBit(
	TEE_BigInt *src,
	uint32_t bitIndex)
{
	BIGNUM *bn_src = BN_new();
	bool result = false;

	if (!bn_src)
		goto error;

	if (BigIntToBN(bn_src, src))
		goto error;

	result = BN_is_bit_set(bn_src, bitIndex) ? true : false;

error:
	BN_clear_free(bn_src);

	return result;
}

uint32_t TEE_BigIntGetBitCount(
	TEE_BigInt *src) {

	uint32_t ret = 0;

	BIGNUM *bn_src = BN_new();
	if (!bn_src)
		goto err1;

	if (BigIntToBN(bn_src, src))
		goto err2;

	ret = (uint32_t) BN_num_bits(bn_src);

err2:
	BN_clear_free(bn_src);
err1:
	return ret;
}

void TEE_BigIntAdd(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2) {
	BIGNUM *result = BN_new();
	BIGNUM *bn_op1 = BN_new();
	BIGNUM *bn_op2 = BN_new();

	if (!result || !bn_op1 || !bn_op2)
		goto error;

	if (BigIntToBN(bn_op1, op1))
		goto error;

	if (BigIntToBN(bn_op2, op2))
		goto error;

	if (!BN_add(result, bn_op1, bn_op2))
	        goto error; // Error happened while adding

	if (BNToBigInt(dest, result))
	        goto error;

error:
	BN_clear_free(result);
	BN_clear_free(bn_op1);
	BN_clear_free(bn_op2);
}

void TEE_BigIntSub(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2) {
	BIGNUM *result = BN_new();
	BIGNUM *bn_op1 = BN_new();
	BIGNUM *bn_op2 = BN_new();

	if (!result || !bn_op1 || !bn_op2)
		goto error;

	if (BigIntToBN(bn_op1, op1))
		goto error;

	if (BigIntToBN(bn_op2, op2))
		goto error;

	if (!BN_sub(result, bn_op1, bn_op2))
	        goto error; // Error happened while substracting

	if (BNToBigInt(dest, result))
	        goto error;

error:
	BN_clear_free(result);
	BN_clear_free(bn_op1);
	BN_clear_free(bn_op2);
}

void TEE_BigIntNeg(TEE_BigInt *dest, TEE_BigInt *op) {

	BIGNUM *bn_op = BN_new();
	if (!bn_op)
		goto error;

	if (BigIntToBN(bn_op, op))
		goto error;

	if (!BN_is_negative(bn_op))
		BN_set_negative(bn_op, 1);

	if (BNToBigInt(dest, bn_op))
	        goto error;

error:
	BN_clear_free(bn_op);
}

void TEE_BigIntMul(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2) {
	BIGNUM *result = BN_new();
	BIGNUM *bn_op1 = BN_new();
	BIGNUM *bn_op2 = BN_new();
	BN_CTX *context = BN_CTX_new();

	if (!context || !result || !bn_op1 || !bn_op2)
		goto error;

	if (BigIntToBN(bn_op1, op1))
		goto error;

	if (BigIntToBN(bn_op2, op2))
		goto error;

	if (!BN_mul(result, bn_op1, bn_op2, context))
	        goto error; // Error happened while multiplying

	if (BNToBigInt(dest, result))
	        goto error;

error:
	BN_CTX_free(context);
	BN_clear_free(result);
	BN_clear_free(bn_op1);
	BN_clear_free(bn_op2);
}

void TEE_BigIntDiv(
	TEE_BigInt *dest_q,
	TEE_BigInt *dest_r,
	TEE_BigInt *op1,
	TEE_BigInt *op2) {
	BIGNUM *div = BN_new();
	BIGNUM *rem = BN_new();
	BIGNUM *bn_op1 = BN_new();
	BIGNUM *bn_op2 = BN_new();
	BN_CTX *context = BN_CTX_new();

	if (!context || !div || !rem || !bn_op1 || !bn_op2)
		goto error;

	if (BigIntToBN(bn_op1, op1))
		goto error;

	if (BigIntToBN(bn_op2, op2))
		goto error;

	if (!BN_div(div, rem, bn_op1, bn_op2, context))
	        goto error; // Error happened while division

	if (BNToBigInt(dest_q, div))
	        goto error;

	if (BNToBigInt(dest_r, rem))
	        goto error;
error:
	BN_CTX_free(context);
	BN_clear_free(div);
	BN_clear_free(rem);
	BN_clear_free(bn_op1);
	BN_clear_free(bn_op2);
}

