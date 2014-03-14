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

	BIGNUM *ret = BN_mpi2bn(data, header->length, dest);
	if (ret == NULL)
		return - 1;

	return 0;
}

static int32_t BNToBigInt(TEE_BigInt *dest, const BIGNUM *src) {
	struct TEE_BigInt_InternalHeader *header =
		(struct TEE_BigInt_InternalHeader *) dest;

	int representation_length = BN_bn2mpi(src, NULL);

	// Check if representation fits in given TEE_BigInt
	if (header->length < (unsigned int)representation_length)
		return -1;

        unsigned char *data =
		&((unsigned char*) dest)
		[sizeof(struct TEE_BigInt_InternalHeader)];

	BN_bn2mpi(src, data);

	return 0;
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

void TEE_BigIntAdd(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2) {
	BIGNUM *result = BN_new();
	BIGNUM *bn_op1 = BN_new();
	BIGNUM *bn_op2 = BN_new();

	if (!result && !bn_op1 && !bn_op2)
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
