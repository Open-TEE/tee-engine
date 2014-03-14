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

/* Constant which tells if FMM context has been initialized. "FMM" in ascii */
static const uint32_t FMM_context_magic = 0x00464D4D;
struct FMMContext {
	uint32_t magic;
	size_t length;
	TEE_BigInt *modulus;
};

/* Memory allocation and Size of Objects */
size_t TEE_BigIntFMMContextSizeInU32(size_t modulusSizeInBits)
{
	return sizeof(struct FMMContext);
}

size_t TEE_BigIntFMMSizeInU32(size_t modulusSizeInBits)
{
	return TEE_BigIntSizeInU32(modulusSizeInBits);
}

/* Initialization Functions */
void TEE_BigIntInit(TEE_BigInt *bigInt, size_t len)
{
	/* Check parameters */
	if (bigInt == NULL || len == 0)
		return;

	/* Fill the memory area with zeros */
	memset(bigInt, 0, len * sizeof(uint32_t));

	struct TEE_BigInt_InternalHeader *header =
		(struct TEE_BigInt_InternalHeader *) bigInt;

	/* Store length to header in the beginning of the array */
	header->length =
		len - (sizeof(struct TEE_BigInt_InternalHeader) /
			sizeof(uint32_t));
}

static bool isFMMContextInitialized(TEE_BigIntFMMContext *context)
{
	if (context == NULL)
		return false;

	struct FMMContext *fmm = context;

	return fmm->magic == FMM_context_magic;
}

void TEE_BigIntInitFMMContext(TEE_BigIntFMMContext *context, size_t len,
			      TEE_BigInt *modulus)
{
	if (context == NULL)
		return;

	struct FMMContext *fmm = context;

	fmm->magic = FMM_context_magic;
	fmm->length = len;
	fmm->modulus = modulus;
}

void TEE_BigIntInitFMM(TEE_BigIntFMM *bigIntFMM, size_t len)
{
	return TEE_BigIntInit((TEE_BigInt *)bigIntFMM, len);
}

/* Internal conversion functions */
static int32_t BigIntToBN(BIGNUM *dest, TEE_BigInt *src)
{
	/* Check parameters */
	if (dest == NULL || src == NULL)
		return -1;
		/* TODO: Some internal error constants */

	/* Cast pointer to header */
	struct TEE_BigInt_InternalHeader *header =
		(struct TEE_BigInt_InternalHeader *) src;

	/* Cast pointer to data */
	unsigned char *data =
		&((unsigned char *) src)
		[sizeof(struct TEE_BigInt_InternalHeader)];

	/* Convert binary data to BIGNUM value */
	BIGNUM *ret = BN_bin2bn(data, header->length, dest);
	if (ret == NULL) {
		printf("BigInt -> BN conversion failed");
		/* TODO: Some internal error constants */
		return -1;
	}

	/* Set signedness of BIGNUM */
	BN_set_negative(ret, header->neg);

	return 0;
}

static int32_t BNToBigInt(TEE_BigInt *dest, const BIGNUM *src)
{
	/* Check parameters */
	if (dest == NULL || src == NULL)
		return -1;
		/* TODO: Some internal error constants */

	/* Cast pointer to header */
	struct TEE_BigInt_InternalHeader *header =
		(struct TEE_BigInt_InternalHeader *) dest;

	int representation_length =
		BN_num_bytes(src) / sizeof(uint32_t);

	/* Check if representation fits in given TEE_BigInt */
	if (header->length < (unsigned int)representation_length) {
		printf("Does not fit %i < %i\n",
				header->length,
				(unsigned int)representation_length);
		/* TODO: Some internal error constants */
		return -1;
	}

	header->neg = BN_is_negative(src) ? 1 : 0;

	/* Cast pointer to data */
	unsigned char *data =
		&((unsigned char *) dest)
		[sizeof(struct TEE_BigInt_InternalHeader)];

	/* Convert BIGNUM value to binary data */
	/* TODO: Returns length of number placed at data-ptr,
	 *       some check. */
	BN_bn2bin(src, data);

	return 0;
}

/* Converter Functions */
TEE_Result TEE_BigIntConvertFromOctetString(TEE_BigInt *dest, uint8_t *buffer,
					    size_t bufferLen, int32_t sign)
{
	TEE_Result ret = TEE_ERROR_OVERFLOW;

	/* Check parameters */
	if (dest == NULL || buffer == NULL)
		goto err1;

	/* Allocate BIGNUM */
	BIGNUM *num = BN_new();
	if (!num)
		goto err1;

	/* Allocate buffer for string */
	char *str = TEE_Malloc(bufferLen + 1, 0);
	if (str == NULL)
		goto err2;

	/* Buffer needs to be copied before giving to OpenSSL BIGNUM API
	 * since it only supports NUL-terminated strings */
	memcpy(str, buffer, bufferLen);
	str[bufferLen] = '\0';

	/* Convert hex string to BIGNUM */
	if (!BN_hex2bn(&num, str))
		goto err3;

	/* Set the sign for read value */
	BN_set_negative(num, sign != 0);

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, num))
		goto err2;

	ret = TEE_SUCCESS;

err3:
	TEE_Free(str);
err2:
	BN_clear_free(num);
err1:
	return ret;
}

TEE_Result TEE_BigIntConvertToOctetString(void *buffer,
					  size_t bufferLen,
					  TEE_BigInt *bigInt)
{
	TEE_Result ret = TEE_ERROR_SHORT_BUFFER;

	/* Check parameters */
	if (buffer == NULL || bigInt == NULL)
		goto err1;

	/* Allocate BIGNUM */
	BIGNUM *num = BN_new();
	if (!num)
		goto err1;

	/* Convert parameter TEE_BigInt -> BIGNUM */
	if (BigIntToBN(num, bigInt))
		goto err2;

	/* Get string representation fom BIGNUM API */
	char *str = BN_bn2hex(num);
	if (!str)
		goto err2;

	/* Check that string and NUL-termination byte
	 * fits into the given buffer
	 */
	size_t length_of_str = strlen(str);
	if (bufferLen < length_of_str + 1)
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

void TEE_BigIntConvertFromS32(TEE_BigInt *dest, int32_t shortVal)
{
	/* Check parameters */
	if (dest == NULL)
		goto err1;

	/* Calculate absolute value of shortVal */
	const uint32_t absVal = shortVal < 0 ? -shortVal : shortVal;

	/* TODO: Might need to change endianess here */
	BIGNUM *bn_dest =
		BN_bin2bn((uint8_t *)(&absVal), sizeof(uint32_t), NULL);
	if (!bn_dest)
		goto err1;

	/* Set the negative sign if needed */
	if (shortVal < 0)
		BN_set_negative(bn_dest, true);

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, bn_dest))
		goto err2;

err2:
	BN_clear_free(bn_dest);
err1:
	return;
}

void TEE_BigIntConvertToS32(int32_t *dest, TEE_BigInt *src)
{
	/* Check parameters */
	if (dest == NULL || src == NULL)
		goto err1;

	/* Allocate BIGNUM */
	BIGNUM *bn_src = BN_new();
	if (!bn_src)
		goto err1;

	/* Convert parameter TEE_BigInt -> BIGNUM */
	if (BigIntToBN(bn_src, src))
		goto err2;

	/* TODO: Check how bignum internal representations work.
	 *       It seems representation_length is 0 when value is 0.
	 *
	 *       There are macros BN_is_zero and BN_is_one in
	 *       BIGNUM api, maybe these should be used?
	 */
	/* TODO: Check signedness of outgoing value */
	/* TODO: Might need to change endianess here */
	const size_t representation_length = BN_num_bytes(bn_src);
	if (representation_length == 0)
		*dest = 0;
	else if (representation_length > 0 && representation_length <= 4)
		BN_bn2bin(bn_src, (uint8_t *)dest);
	else {
		printf("Too big representation");
		goto err2;
	}

err2:
	BN_clear_free(bn_src);
err1:
	return;
}

/* Logical Operations */
int32_t TEE_BigIntCmp(TEE_BigInt *op1, TEE_BigInt *op2)
{
	/* TODO: Figure out reasonable error value */
	int32_t ret = -200;

	/* Check parameters */
	if (op1 == NULL || op2 == NULL)
		goto err1;

	/* Allocate BIGNUMs */
	BIGNUM *bn_op1 = BN_new();
	if (!bn_op1)
		goto err1;

	BIGNUM *bn_op2 = BN_new();
	if (!bn_op2)
		goto err2;

	/* Convert parameter TEE_BigInt -> BIGNUM */
	if (BigIntToBN(bn_op1, op1))
		goto err3;

	if (BigIntToBN(bn_op2, op2))
		goto err3;

	/* Do the comparison */
	ret = BN_cmp(bn_op1, bn_op2);

err3:
	BN_clear_free(bn_op1);
err2:
	BN_clear_free(bn_op2);
err1:
	return ret;
}

int32_t TEE_BigIntCmpS32(TEE_BigInt *op1, int32_t shortVal)
{
	/* Check parameters */
	/* TODO: Figure out reasonable error value */
	if (op1 == NULL)
		return -200;

	/* Statically allocate space for TEE_BigInt and initialize*/
	TEE_BigInt op2[TEE_BigIntSizeInU32(32)];
	TEE_BigIntInit(op2, TEE_BigIntSizeInU32(32));

	/* Convert int32_t -> TEE_BigInt */
	TEE_BigIntConvertFromS32(op2, shortVal);

	return TEE_BigIntCmp(op1, op2);
}

void TEE_BigIntShiftRight(TEE_BigInt *dest, TEE_BigInt *op, size_t bits)
{
	/* Check parameters */
	if (dest == NULL || op == NULL)
		goto err1;

	/* Allocate BIGNUMs */
	BIGNUM *result = BN_new();
	if (!result)
		goto err1;

	BIGNUM *bn_op = BN_new();
	if (!bn_op)
		goto err2;

	/* Convert parameter TEE_BigInt -> BIGNUM */
	if (BigIntToBN(bn_op, op))
		goto err3;

	/* Do the right shift */
	if (!BN_rshift(result, bn_op, bits))
		goto err3;

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, result))
		goto err3;

err3:
	BN_clear_free(bn_op);
err2:
	BN_clear_free(result);
err1:
	return;
}

bool TEE_BigIntGetBit(TEE_BigInt *src, uint32_t bitIndex)
{
	bool ret = false;

	/* Check parameters */
	if (src == NULL)
		goto err1;

	/* Allocate BIGNUM */
	BIGNUM *bn_src = BN_new();
	if (!bn_src)
		goto err1;

	/* Convert parameter TEE_BigInt -> BIGNUM */
	if (BigIntToBN(bn_src, src))
		goto err2;

	/* Check bit status using bignum api */
	ret = BN_is_bit_set(bn_src, bitIndex) ? true : false;

err2:
	BN_clear_free(bn_src);
err1:
	return ret;
}

uint32_t TEE_BigIntGetBitCount(TEE_BigInt *src)
{
	uint32_t ret = 0;

	/* Check parameters */
	if (src == NULL)
		goto err1;

	/* Allocate BIGNUM */
	BIGNUM *bn_src = BN_new();
	if (!bn_src)
		goto err1;

	/* Convert parameter TEE_BigInt -> BIGNUM */
	if (BigIntToBN(bn_src, src))
		goto err2;

	/* Calculate bits using bignum api */
	/* TODO: Check if this really is magnitude or something else */
	ret = (uint32_t) BN_num_bits(bn_src);

err2:
	BN_clear_free(bn_src);
err1:
	return ret;
}

/* Basic Arithmetic Operations */
void TEE_BigIntAdd(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2)
{
	/* Check parameters */
	if (dest == NULL || op1 == NULL || op2 == NULL)
		goto err1;

	/* Allocate BIGNUMs */
	BIGNUM *result = BN_new();
	if (!result)
		goto err1;

	BIGNUM *bn_op1 = BN_new();
	if (!bn_op1)
		goto err2;

	BIGNUM *bn_op2 = BN_new();
	if (!bn_op2)
		goto err3;

	/* Convert parameter TEE_BigInt -> BIGNUM */
	if (BigIntToBN(bn_op1, op1))
		goto err4;

	if (BigIntToBN(bn_op2, op2))
		goto err4;

	/* Do adding */
	if (!BN_add(result, bn_op1, bn_op2))
		goto err4;

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, result))
		goto err4;

err4:
	BN_clear_free(bn_op2);
err3:
	BN_clear_free(bn_op1);
err2:
	BN_clear_free(result);
err1:
	return;
}

void TEE_BigIntSub(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2)
{
	/* Check parameters */
	if (dest == NULL || op1 == NULL || op2 == NULL)
		goto err1;

	/* Allocate BIGNUMs */
	BIGNUM *result = BN_new();
	if (!result)
		goto err1;

	BIGNUM *bn_op1 = BN_new();
	if (!bn_op1)
		goto err2;

	BIGNUM *bn_op2 = BN_new();
	if (!bn_op2)
		goto err3;

	/* Convert parameter TEE_BigInt -> BIGNUM */
	if (BigIntToBN(bn_op1, op1))
		goto err4;

	if (BigIntToBN(bn_op2, op2))
		goto err4;

	/* Do substraction */
	if (!BN_sub(result, bn_op1, bn_op2))
		goto err4;

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, result))
		goto err4;

err4:
	BN_clear_free(bn_op2);
err3:
	BN_clear_free(bn_op1);
err2:
	BN_clear_free(result);
err1:
	return;
}

void TEE_BigIntNeg(TEE_BigInt *dest, TEE_BigInt *op)
{
	/* Check parameters */
	if (dest == NULL || op == NULL)
		goto err1;

	/* Allocate BIGNUM */
	BIGNUM *bn_op = BN_new();
	if (!bn_op)
		goto err1;

	/* Convert parameter TEE_BigInt -> BIGNUM */
	if (BigIntToBN(bn_op, op))
		goto err2;

	/* Change sign */
	BN_set_negative(bn_op, !BN_is_negative(bn_op));

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, bn_op))
		goto err2;

err2:
	BN_clear_free(bn_op);
err1:
	return;
}

void TEE_BigIntMul(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2)
{
	/* Check parameters */
	if (dest == NULL || op1 == NULL || op2 == NULL)
		goto err1;

	/* Allocate BIGNUMs */
	BIGNUM *result = BN_new();
	if (!result)
		goto err1;

	BIGNUM *bn_op1 = BN_new();
	if (!bn_op1)
		goto err2;

	BIGNUM *bn_op2 = BN_new();
	if (!bn_op2)
		goto err3;

	/* Convert parameter TEE_BigInt -> BIGNUM */
	if (BigIntToBN(bn_op1, op1))
		goto err4;

	if (BigIntToBN(bn_op2, op2))
		goto err4;

	/* Create context for multiplication */
	BN_CTX *context = BN_CTX_new();
	if (!context)
		goto err4;

	/* Do multiplication */
	if (!BN_mul(result, bn_op1, bn_op2, context))
		goto err5;

	/* Convert result BIGN^M -> TEE_BigInt */
	if (BNToBigInt(dest, result))
		goto err5;

err5:
	BN_CTX_free(context);
err4:
	BN_clear_free(bn_op2);
err3:
	BN_clear_free(bn_op1);
err2:
	BN_clear_free(result);
err1:
	return;
}

void TEE_BigIntSquare(TEE_BigInt *dest, TEE_BigInt *op)
{
	/* Check parameters */
	if (dest == NULL || op == NULL)
		goto err1;

	/* Allocate BIGNUM */
	BIGNUM *bn_op = BN_new();
	if (!bn_op)
		goto err1;

	/* Convert parameter TEE_BigInt -> BIGNUM */
	if (BigIntToBN(bn_op, op))
		goto err2;

	/* Create context for squarification */
	BN_CTX *context = BN_CTX_new();
	if (!context)
		goto err2;

	/* Teke the square of op */
	if (!BN_sqr(bn_op, bn_op, context))
		goto err3;

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, bn_op))
		goto err3;

err3:
	BN_CTX_free(context);
err2:
	BN_clear_free(bn_op);
err1:
	return;
}

void TEE_BigIntDiv(TEE_BigInt *dest_q, TEE_BigInt *dest_r,
		   TEE_BigInt *op1, TEE_BigInt *op2)
{
	/* Check parameters */
	if (dest_q == NULL || dest_r == NULL || op1 == NULL || op2 == NULL)
		goto err1;

	/* Allocate BIGNUMs */
	BIGNUM *div = BN_new();
	if (!div)
		goto err1;

	BIGNUM *rem = BN_new();
	if (!rem)
		goto err2;

	BIGNUM *bn_op1 = BN_new();
	if (!bn_op1)
		goto err3;

	BIGNUM *bn_op2 = BN_new();
	if (!bn_op2)
		goto err4;

	/* Convert parameter TEE_BigInt -> BIGNUM */
	if (BigIntToBN(bn_op1, op1))
		goto err5;

	if (BigIntToBN(bn_op2, op2))
		goto err5;

	if (BN_is_zero(bn_op2)) {
		/* TODO: How to panic? */
		printf("Panic Reason op2 == 0");
		goto err5;
	}

	/* Create context for division */
	BN_CTX *context = BN_CTX_new();
	if (!context)
		goto err5;

	/* Do the division */
	if (!BN_div(div, rem, bn_op1, bn_op2, context))
		goto err6;

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest_q, div))
		goto err6;

	if (BNToBigInt(dest_r, rem))
		goto err6;

err6:
	BN_CTX_free(context);
err5:
	BN_clear_free(bn_op2);
err4:
	BN_clear_free(bn_op1);
err3:
	BN_clear_free(rem);
err2:
	BN_clear_free(div);
err1:
	return;
}

/* Modular Arithmetic Operations */
void TEE_BigIntMod(TEE_BigInt *dest, TEE_BigInt *op, TEE_BigInt *n)
{
	/* Check parameters */
	if (dest == NULL || op == NULL || n == NULL)
		goto err1;

	/* Allocate BIGNUMs */
	BIGNUM *result = BN_new();
	if (!result)
		goto err1;

	BIGNUM *bn_op = BN_new();
	if (!bn_op)
		goto err2;

	BIGNUM *bn_n = BN_new();
	if (!bn_n)
		goto err3;

	/* Convert parameter TEE_BigInt -> BIGNUM */
	if (BigIntToBN(bn_op, op))
		goto err4;

	/* Create context for operation */
	BN_CTX *context = BN_CTX_new();
	if (!context)
		goto err4;

	/* Do adding */
	if (!BN_mod(result, bn_op, bn_n, context))
		goto err5;

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, result))
		goto err5;

err5:
	BN_CTX_free(context);
err4:
	BN_clear_free(bn_n);
err3:
	BN_clear_free(bn_op);
err2:
	BN_clear_free(result);
err1:
	return;
}

void TEE_BigIntAddMod(TEE_BigInt *dest, TEE_BigInt *op1,
		      TEE_BigInt *op2, TEE_BigInt *n)
{
	/* Check parameters */
	if (dest == NULL || op1 == NULL || op2 == NULL || n == NULL)
		goto err1;

	/* Allocate BIGNUMs */
	BIGNUM *result = BN_new();
	if (!result)
		goto err1;

	BIGNUM *bn_op1 = BN_new();
	if (!bn_op1)
		goto err2;

	BIGNUM *bn_op2 = BN_new();
	if (!bn_op2)
		goto err3;

	BIGNUM *bn_n = BN_new();
	if (!bn_n)
		goto err4;

	/* Convert parameter TEE_BigInt -> BIGNUM */
	if (BigIntToBN(bn_op1, op1))
		goto err5;

	if (BigIntToBN(bn_op2, op2))
		goto err5;

	/* Create context for operation */
	BN_CTX *context = BN_CTX_new();
	if (!context)
		goto err5;

	/* Do adding */
	if (!BN_mod_add(result, bn_op1, bn_op2, bn_n, context))
		goto err6;

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, result))
		goto err6;

err6:
	BN_CTX_free(context);
err5:
	BN_clear_free(bn_n);
err4:
	BN_clear_free(bn_op2);
err3:
	BN_clear_free(bn_op1);
err2:
	BN_clear_free(result);
err1:
	return;
}

void TEE_BigIntSubMod(TEE_BigInt *dest, TEE_BigInt *op1,
		      TEE_BigInt *op2, TEE_BigInt *n)
{
	/* Check parameters */
	if (dest == NULL || op1 == NULL || op2 == NULL || n == NULL)
		goto err1;

	/* Allocate BIGNUMs */
	BIGNUM *result = BN_new();
	if (!result)
		goto err1;

	BIGNUM *bn_op1 = BN_new();
	if (!bn_op1)
		goto err2;

	BIGNUM *bn_op2 = BN_new();
	if (!bn_op2)
		goto err3;

	BIGNUM *bn_n = BN_new();
	if (!bn_n)
		goto err4;

	/* Convert parameter TEE_BigInt -> BIGNUM */
	if (BigIntToBN(bn_op1, op1))
		goto err5;

	if (BigIntToBN(bn_op2, op2))
		goto err5;

	/* Create context for operation */
	BN_CTX *context = BN_CTX_new();
	if (!context)
		goto err5;

	/* Do substraction */
	if (!BN_mod_sub(result, bn_op1, bn_op2, bn_n, context))
		goto err6;

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, result))
		goto err6;

err6:
	BN_CTX_free(context);
err5:
	BN_clear_free(bn_n);
err4:
	BN_clear_free(bn_op2);
err3:
	BN_clear_free(bn_op1);
err2:
	BN_clear_free(result);
err1:
	return;
}

void TEE_BigIntMulMod(TEE_BigInt *dest, TEE_BigInt *op1,
		      TEE_BigInt *op2, TEE_BigInt *n)
{
	/* Check parameters */
	if (dest == NULL || op1 == NULL || op2 == NULL || n == NULL)
		goto err1;

	/* Allocate BIGNUMs */
	BIGNUM *result = BN_new();
	if (!result)
		goto err1;

	BIGNUM *bn_op1 = BN_new();
	if (!bn_op1)
		goto err2;

	BIGNUM *bn_op2 = BN_new();
	if (!bn_op2)
		goto err3;

	BIGNUM *bn_n = BN_new();
	if (!bn_n)
		goto err4;

	/* Convert parameter TEE_BigInt -> BIGNUM */
	if (BigIntToBN(bn_op1, op1))
		goto err5;

	if (BigIntToBN(bn_op2, op2))
		goto err5;

	/* Create context for operation */
	BN_CTX *context = BN_CTX_new();
	if (!context)
		goto err5;

	/* Do multiplication */
	if (!BN_mod_mul(result, bn_op1, bn_op2, bn_n, context))
		goto err6;

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, result))
		goto err6;

err6:
	BN_CTX_free(context);
err5:
	BN_clear_free(bn_n);
err4:
	BN_clear_free(bn_op2);
err3:
	BN_clear_free(bn_op1);
err2:
	BN_clear_free(result);
err1:
	return;
}

void TEE_BigIntSquareMod(TEE_BigInt *dest, TEE_BigInt *op, TEE_BigInt *n)
{
	/* Check parameters */
	if (dest == NULL || op == NULL || n == NULL)
		goto err1;

	/* Allocate BIGNUMs */
	BIGNUM *result = BN_new();
	if (!result)
		goto err1;

	BIGNUM *bn_op = BN_new();
	if (!bn_op)
		goto err2;

	BIGNUM *bn_n = BN_new();
	if (!bn_n)
		goto err3;

	/* Convert parameter TEE_BigInt -> BIGNUM */
	if (BigIntToBN(bn_op, op))
		goto err4;

	/* Create context for operation */
	BN_CTX *context = BN_CTX_new();
	if (!context)
		goto err4;

	/* Take square */
	if (!BN_mod_sqr(result, bn_op, bn_n, context))
		goto err5;

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, result))
		goto err5;

err5:
	BN_CTX_free(context);
err4:
	BN_clear_free(bn_n);
err3:
	BN_clear_free(bn_op);
err2:
	BN_clear_free(result);
err1:
	return;
}

void TEE_BigIntInvMod(TEE_BigInt *dest, TEE_BigInt *op, TEE_BigInt *n)
{
	/* Check parameters */
	if (dest == NULL || op == NULL || n == NULL)
		goto err1;

	/* Allocate BIGNUMs */
	BIGNUM *result = BN_new();
	if (!result)
		goto err1;

	BIGNUM *bn_op = BN_new();
	if (!bn_op)
		goto err2;

	BIGNUM *bn_n = BN_new();
	if (!bn_n)
		goto err3;

	/* Convert parameter TEE_BigInt -> BIGNUM */
	if (BigIntToBN(bn_op, op))
		goto err4;

	/* Create context for operation */
	BN_CTX *context = BN_CTX_new();
	if (!context)
		goto err4;

	/* Take inverse mod */
	if (!BN_mod_inverse(result, bn_op, bn_n, context))
		goto err5;

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, result))
		goto err5;

err5:
	BN_CTX_free(context);
err4:
	BN_clear_free(bn_n);
err3:
	BN_clear_free(bn_op);
err2:
	BN_clear_free(result);
err1:
	return;
}

/* Other Arithmetic Operations */
bool TEE_BigIntRelativePrime(TEE_BigInt *op1, TEE_BigInt *op2)
{
	bool ret = false;

	/* Check parameters */
	if (op1 == NULL || op2 == NULL)
		goto err1;

	/* Allocate BIGNUMs */
	BIGNUM *result = BN_new();
	if (!result)
		goto err1;

	BIGNUM *bn_op1 = BN_new();
	if (!bn_op1)
		goto err2;

	BIGNUM *bn_op2 = BN_new();
	if (!bn_op2)
		goto err3;

	/* Convert parameter TEE_BigInt -> BIGNUM */
	if (BigIntToBN(bn_op1, op1))
		goto err4;

	if (BigIntToBN(bn_op2, op2))
		goto err4;

	/* Create context for operation */
	BN_CTX *context = BN_CTX_new();
	if (!context)
		goto err4;

	/* Calculate gcd */
	if (!BN_gcd(result, bn_op1, bn_op2, context))
		goto err5;

	/* Return value is true if gcd(op1, op2) == 1 */
	ret = BN_is_one(result) ? true : false;

err5:
	BN_CTX_free(context);
err4:
	BN_clear_free(bn_op2);
err3:
	BN_clear_free(bn_op1);
err2:
	BN_clear_free(result);
err1:
	return ret;
}

/*
struct egcd_recurse_out
{
	BIGNUM *gcd;
	BIGNUM *u;
	BIGNUM *v;
};

static struct egcd_recurse_out egcd_recurse(const BIGNUM *x, const BIGNUM *y)
{
	struct egcd_recurse_out ret;

	ret.gcd = BN_new();
	if (ret.gcd == NULL)
		return ret;

	ret.u = BN_new();
	if (ret.u == NULL)
		return ret;

	ret.v = BN_new();
	if (ret.v == NULL)
		return ret;

	if (BN_is_zero(y))
	{
		BN_copy(ret.gcd, x);
		BN_set_word(ret.x, 1);
		BN_set_word(ret.y, 0);
	}
	else
	{
		ret = egcd_recurse(y, mod_x_y);
	}

	return ret;
}
*/

void TEE_BigIntComputeExtendedGcd(TEE_BigInt *gcd, TEE_BigInt *u,
				  TEE_BigInt *v, TEE_BigInt *op1,
				  TEE_BigInt *op2)
{
	/* Check parameters */
	if (gcd == NULL || op1 == NULL || op2 == NULL)
		goto err1;

	/* Allocate BIGNUMs */
	BIGNUM *bn_gcd = BN_new();
	if (!bn_gcd)
		goto err1;

	BIGNUM *bn_op1 = BN_new();
	if (!bn_op1)
		goto err2;

	BIGNUM *bn_op2 = BN_new();
	if (!bn_op2)
		goto err3;

	BIGNUM *bn_u = BN_new();
	if (!bn_u)
		goto err4;

	BIGNUM *bn_v = BN_new();
	if (!bn_v)
		goto err5;

	/* Convert parameter TEE_BigInt -> BIGNUM */
	if (BigIntToBN(bn_op1, op1))
		goto err6;

	if (BigIntToBN(bn_op2, op2))
		goto err6;

	/* Create context for operation */
	BN_CTX *context = BN_CTX_new();
	if (!context)
		goto err6;

	/* TODO: The actual egcd algorithm */

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(gcd, bn_gcd))
		goto err7;

	if (BNToBigInt(u, bn_u))
		goto err7;

	if (BNToBigInt(v, bn_v))
		goto err7;

err7:
	BN_CTX_free(context);
err6:
	BN_clear_free(bn_v);
err5:
	BN_clear_free(bn_u);
err4:
	BN_clear_free(bn_op2);
err3:
	BN_clear_free(bn_op1);
err2:
	BN_clear_free(bn_gcd);
err1:
	return;
}

int32_t TEE_BigIntIsProbablePrime(TEE_BigInt *op, uint32_t confidenceLevel)
{
	int32_t ret = 0;

	/* Values smaller than 80 will be treated as 80 */
	confidenceLevel = confidenceLevel < 80 ? 80 : confidenceLevel;

	/* Parameter check */
	if (op == NULL)
		goto err1;

	/* Allocate BIGNUM */
	BIGNUM *bn_op = BN_new();
	if (!bn_op)
		goto err1;

	/* Convert parameter TEE_BigInt -> BIGNUM */
	if (BigIntToBN(bn_op, op))
		goto err2;

	/* Create context for operation */
	BN_CTX *context = BN_CTX_new();
	if (!context)
		goto err3;

	/* TODO: How to check for "guaranteed prime" */

	int32_t result = BN_is_prime_ex(bn_op, confidenceLevel, context, NULL);
	if (result == -1)
		goto err3;
	else if (result == 1)
		ret = -1;

err3:
	BN_CTX_free(context);
err2:
	BN_clear_free(bn_op);
err1:
	return ret;
}

/* Fast Modular Multiplication Operations */
void TEE_BigIntConvertToFMM(TEE_BigIntFMM *dest, TEE_BigInt *src,
			    TEE_BigInt *n, TEE_BigIntFMMContext *context)
{
	/* TODO: Context-related Initialization checks */
	struct TEE_BigInt_InternalHeader *src_header =
		(struct TEE_BigInt_InternalHeader *) src;

	size_t src_len = src_header->length +
		(sizeof(struct TEE_BigInt_InternalHeader) / sizeof(uint32_t));

	memcpy(dest, src, src_len);

	return;
}

void TEE_BigIntConvertFromFMM(TEE_BigInt *dest, TEE_BigIntFMM *src,
			      TEE_BigInt *n, TEE_BigIntFMMContext *context)
{
	/* TODO: Context-related Initialization checks */
	struct TEE_BigInt_InternalHeader *src_header =
		(struct TEE_BigInt_InternalHeader *) src;

	size_t src_len = src_header->length +
		(sizeof(struct TEE_BigInt_InternalHeader) / sizeof(uint32_t));

	memcpy(dest, src, src_len);

	return;
}

void TEE_BigIntComputeFMM(TEE_BigIntFMM *dest, TEE_BigIntFMM *op1,
			  TEE_BigIntFMM *op2, TEE_BigInt *n,
			  TEE_BigIntFMMContext *context)
{
	/* TODO: Context-related Initialization checks */
	return TEE_BigIntMulMod(dest, op1, op2, n);
}

