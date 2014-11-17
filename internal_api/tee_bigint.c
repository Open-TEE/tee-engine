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
#include "tee_panic.h"

#include <openssl/bn.h>
#include <openssl/err.h>

/* For endianness functions */
#include <arpa/inet.h>

#include <string.h>

/* Constant that tells if FMM context has been initialized. "FMM" in ascii */
static const uint32_t FMM_context_magic = 0x00464D4D;
struct FMMContext {
	uint32_t magic;
	size_t length;
	TEE_BigInt *modulus;
};

/* Memory allocation and Size of Objects */
size_t TEE_BigIntFMMContextSizeInU32(size_t modulusSizeInBits)
{
	return sizeof(struct FMMContext)
		+ (modulusSizeInBits * 0); /* to suppress unused parameter warning */
}

size_t TEE_BigIntFMMSizeInU32(size_t modulusSizeInBits)
{
	return TEE_BigIntSizeInU32(modulusSizeInBits);
}

static inline struct TEE_BigInt_InternalHeader *GetHeader(TEE_BigInt *bigInt)
{
	return (struct TEE_BigInt_InternalHeader *)bigInt;
}

static inline unsigned char *GetData(TEE_BigInt *bigInt)
{
	return (unsigned char *)bigInt + sizeof(struct TEE_BigInt_InternalHeader);
}

/* Initialization Functions */
void TEE_BigIntInit(TEE_BigInt *bigInt, size_t len)
{
	/* Check parameters */
	if (bigInt == NULL || len == 0)
		return;

	/* Fill the memory area with zeros */
	memset(bigInt, 0, len * sizeof(uint32_t));

	/* Store length to header in the beginning of the array */
	GetHeader(bigInt)->allocated_u32s =
		len - (sizeof(struct TEE_BigInt_InternalHeader) / sizeof(uint32_t));
}

void TEE_BigIntInitFMMContext(TEE_BigIntFMMContext *context, size_t len,
			      TEE_BigInt *modulus)
{
	if (context == NULL)
		return;

	struct FMMContext *fmm = (struct FMMContext *)context;

	fmm->magic = FMM_context_magic;
	fmm->length = len;
	fmm->modulus = modulus;
}

void TEE_BigIntInitFMM(TEE_BigIntFMM *bigIntFMM, size_t len)
{
	return TEE_BigIntInit((TEE_BigInt *)bigIntFMM, len);
}

/***
 * Convert from our representation to OpenSSL BIGNUM
 * @param dest Pointer to OpenSSL BIGNUM
 * @param src Pointer to TEE_BigInt representation
 * @return 0 on success, error code otherwise
 */
static int32_t BigIntToBN(BIGNUM *dest, TEE_BigInt *src)
{
	/* Check parameters */
	if (dest == NULL || src == NULL)
		return -1;
		/* TODO: Some internal error constants */

	/* Convert binary data to BIGNUM value */
	/* Returns same pointer than it takes, and null on error */
	BIGNUM *ret = BN_bin2bn(GetData(src),
				GetHeader(src)->bytes_used_by_representation,
				dest);
	if (ret == NULL || ret != dest) {
		printf("BigInt -> BN conversion failed");
		/* TODO: Some internal error constants */
		/* TODO: Panic here! */
		return -1;
	}

	/* Set signedness of BIGNUM */
	BN_set_negative(ret, GetHeader(src)->flags & TEE_BIGINT_FLAGS_NEGATIVE);

	return 0;
}

/***
 * Internal convenience function to be used in beginning of functions.
 * Converts TEE_BigInt representation to OpenSSL BIGNUM
 * @param TEE_BigInt GlobalPlatform style
 * @return NULL on error, Pointer to BIGNUM otherwise
 */
static BIGNUM *AllocAndConvert(TEE_BigInt *src)
{
	BIGNUM *ret = BN_new();
	if (src == NULL || ret == NULL || BigIntToBN(ret, src)) {
		/* Fail */
		BN_clear_free(ret);
		return NULL;
	} else
		return ret;
}

/***
 * Convert from OpenSSL BIGNUM to our representation
 * @param dest Pointer to TEE_BigInt representation
 * @param src Pointer to OpenSSL BIGNUM
 * @return 0 on success, error code otherwise
 */
static int32_t BNToBigInt(TEE_BigInt *dest, const BIGNUM *src)
{
	int written_length = 0;

	/* Check parameters */
	if (dest == NULL || src == NULL)
		return -1;
		/* TODO: Some internal error constants */

	/* Cast pointer to header */
	struct TEE_BigInt_InternalHeader * const header = GetHeader(dest);
	const size_t representation_length = BN_num_bytes(src);

	/* Check if representation fits in given TEE_BigInt */
	if (header->allocated_u32s * sizeof(uint32_t) < representation_length) {
		printf("BigNum representation of %zu does not fit into %zu\n",
		       representation_length,
		       header->allocated_u32s * sizeof(uint32_t));
		/* TODO: Some internal error constants */
		return -1;
	}

	header->flags = BN_is_negative(src) ? TEE_BIGINT_FLAGS_NEGATIVE : 0;

	/* Clear data first */
	memset(GetData(dest), 0, header->allocated_u32s * sizeof(uint32_t));

	/* Convert BIGNUM value to binary data */
	written_length = BN_bn2bin(src, GetData(dest));
	if (written_length < 0 || (size_t) written_length != representation_length)
		return -1;

	header->bytes_used_by_representation = written_length;

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
	if (num == NULL)
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
	BIGNUM *num = AllocAndConvert(bigInt);
	if (num == NULL)
		goto err1;

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

	/* Calculate absolute value of shortVal and change from host order to big endian */
	const uint32_t absVal = htonl(shortVal < 0 ? -shortVal : shortVal);

	BIGNUM *bn_dest =
		BN_bin2bn((uint8_t *)(&absVal), sizeof(uint32_t), NULL);
	if (bn_dest == NULL)
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

TEE_Result TEE_BigIntConvertToS32(int32_t *dest, TEE_BigInt *src)
{
	TEE_Result ret = TEE_SUCCESS;
	BIGNUM *bn_src = NULL;

	/* Check parameters */
	if (dest == NULL || src == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Allocate BIGNUM */
	bn_src = AllocAndConvert(src);
	if (bn_src == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	const size_t representation_length = BN_num_bytes(bn_src);
	if (representation_length == 0)
		/* OpenSSL BigNum library uses repr. length 0 when value is 0 */
		*dest = 0;
	else if (representation_length > 0 && representation_length <= sizeof(uint32_t)) {
		*dest = 0;
		BN_bn2bin(bn_src, (uint8_t *)dest + (sizeof(uint32_t) - representation_length));

		/* Change endianness from big endian to host order */
		/* Multiply with -1 if negative number */
		*dest = (ntohl(*dest) & (~(1 << 31))) * (BN_is_negative(bn_src) ? -1 : 1);
	} else {
		ret = TEE_ERROR_OVERFLOW;
	}

	BN_clear_free(bn_src);
	return ret;
}

/* Logical Operations */
int32_t TEE_BigIntCmp(TEE_BigInt *op1, TEE_BigInt *op2)
{
	/* TODO: Figure out reasonable error value */
	int32_t ret = -200;

	/* Check parameters */
	if (op1 == NULL || op2 == NULL)
		goto err1;

	/* Check if same */
	if (op1 == op2) {
		ret = 0;
		goto err1;
	}

	/* Allocate BIGNUMs */
	BIGNUM *bn_op1 = AllocAndConvert(op1);
	BIGNUM *bn_op2 = AllocAndConvert(op2);
	if (bn_op1 == NULL || bn_op2 == NULL)
		goto err2;

	/* Do the comparison */
	ret = BN_cmp(bn_op1, bn_op2);

err2:
	BN_clear_free(bn_op1);
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
	BIGNUM *bn_op = AllocAndConvert(op);
	if (result == NULL || bn_op == NULL)
		goto err2;

	/* Do the right shift */
	if (!BN_rshift(result, bn_op, bits))
		goto err2;

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, result))
		goto err2;

err2:
	BN_clear_free(bn_op);
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
	BIGNUM *bn_src = AllocAndConvert(src);
	if (bn_src == NULL)
		goto err1;

	/* Check bit status using bignum api */
	ret = BN_is_bit_set(bn_src, bitIndex) ? true : false;

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
	BIGNUM *bn_src = AllocAndConvert(src);
	if (bn_src == NULL)
		goto err1;

	/* Calculate bits using bignum api */
	ret = (uint32_t) BN_num_bits(bn_src);

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
	BIGNUM *bn_op1 = AllocAndConvert(op1);
	BIGNUM *bn_op2 = AllocAndConvert(op2);
	if (result == NULL || bn_op1 == NULL || bn_op2 == NULL)
		goto err2;

	/* Do adding */
	if (!BN_add(result, bn_op1, bn_op2))
		goto err2;

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, result))
		goto err2;

err2:
	BN_clear_free(bn_op2);
	BN_clear_free(bn_op1);
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
	BIGNUM *bn_op1 = AllocAndConvert(op1);
	BIGNUM *bn_op2 = AllocAndConvert(op2);
	if (result == NULL || bn_op1 == NULL || bn_op2 == NULL)
		goto err2;

	/* Do substraction */
	if (!BN_sub(result, bn_op1, bn_op2))
		goto err2;

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, result))
		goto err2;

err2:
	BN_clear_free(bn_op2);
	BN_clear_free(bn_op1);
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
	BIGNUM *bn_op = AllocAndConvert(op);
	if (bn_op == NULL)
		goto err1;

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
	BIGNUM *bn_op1 = AllocAndConvert(op1);
	BIGNUM *bn_op2 = AllocAndConvert(op2);
	if (result == NULL || bn_op1 == NULL || bn_op2 == NULL)
		goto err2;

	/* Create context for multiplication */
	BN_CTX *context = BN_CTX_new();
	if (!context)
		goto err2;

	/* Do multiplication */
	if (!BN_mul(result, bn_op1, bn_op2, context))
		goto err3;

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, result))
		goto err3;

err3:
	BN_CTX_free(context);
err2:
	BN_clear_free(bn_op2);
	BN_clear_free(bn_op1);
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
	BIGNUM *bn_op = AllocAndConvert(op);
	if (bn_op == NULL)
		goto err1;

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
	BIGNUM *rem = BN_new();
	BIGNUM *bn_op1 = AllocAndConvert(op1);
	BIGNUM *bn_op2 = AllocAndConvert(op2);
	if (div == NULL || rem == NULL || bn_op1 == NULL || bn_op2 == NULL)
		goto err2;

	/* Create context for division */
	BN_CTX *context = BN_CTX_new();
	if (!context)
		goto err2;

	/* Do the division */
	if (!BN_div(div, rem, bn_op1, bn_op2, context))
		goto err3;

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest_q, div))
		goto err3;

	if (BNToBigInt(dest_r, rem))
		goto err3;

err3:
	BN_CTX_free(context);
err2:
	BN_clear_free(bn_op2);
	BN_clear_free(bn_op1);
	BN_clear_free(rem);
	BN_clear_free(div);
err1:
	return;
}

/* Modular Arithmetic Operations */
void TEE_BigIntMod(TEE_BigInt *dest, TEE_BigInt *op, TEE_BigInt *n)
{
	BIGNUM *result;
	BIGNUM *bn_op;
	BIGNUM *bn_n;
	BN_CTX *context;

	/* Check parameters */
	if (dest == NULL || op == NULL || n == NULL)
		goto err1;

	/* Allocate BIGNUMs */
	result = BN_new();
	bn_op = AllocAndConvert(op);
	bn_n = AllocAndConvert(n);
	if (result == NULL || bn_op == NULL || bn_n == NULL)
		goto err2;

	/* Create context for operation */
	context = BN_CTX_new();
	if (!context)
		goto err2;

	/* Do adding */
	if (!BN_mod(result, bn_op, bn_n, context))
		goto err3;

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, result))
		goto err3;

err3:
	BN_CTX_free(context);
err2:
	BN_clear_free(bn_n);
	BN_clear_free(bn_op);
	BN_clear_free(result);
err1:
	return;
}

void TEE_BigIntAddMod(TEE_BigInt *dest, TEE_BigInt *op1,
		      TEE_BigInt *op2, TEE_BigInt *n)
{
	BIGNUM *result;
	BIGNUM *bn_op1;
	BIGNUM *bn_op2;
	BIGNUM *bn_n;
	BN_CTX *context;

	/* Check parameters */
	if (dest == NULL || op1 == NULL || op2 == NULL || n == NULL)
		goto err1;

	/* Allocate BIGNUMs */
	result = BN_new();
	bn_op1 = AllocAndConvert(op1);
	bn_op2 = AllocAndConvert(op2);
	bn_n = AllocAndConvert(n);
	if (result == NULL || bn_op1 == NULL || bn_op2 == NULL || bn_n == NULL)
		goto err2;

	/* Create context for operation */
	context = BN_CTX_new();
	if (!context)
		goto err2;

	/* Do adding */
	if (!BN_mod_add(result, bn_op1, bn_op2, bn_n, context))
		goto err3;

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, result))
		goto err3;

err3:
	BN_CTX_free(context);
err2:
	BN_clear_free(bn_n);
	BN_clear_free(bn_op2);
	BN_clear_free(bn_op1);
	BN_clear_free(result);
err1:
	return;
}

void TEE_BigIntSubMod(TEE_BigInt *dest, TEE_BigInt *op1,
		      TEE_BigInt *op2, TEE_BigInt *n)
{
	BIGNUM *result;
	BIGNUM *bn_op1;
	BIGNUM *bn_op2;
	BIGNUM *bn_n;
	BN_CTX *context;

	/* Check parameters */
	if (dest == NULL || op1 == NULL || op2 == NULL || n == NULL)
		goto err1;

	/* Allocate BIGNUMs */
	result = BN_new();
	bn_op1 = AllocAndConvert(op1);
	bn_op2 = AllocAndConvert(op2);
	bn_n = AllocAndConvert(n);
	if (result == NULL || bn_op1 == NULL || bn_op2 == NULL || bn_n == NULL)
		goto err2;

	/* Create context for operation */
	context = BN_CTX_new();
	if (!context)
		goto err2;

	/* Do substraction */
	if (!BN_mod_sub(result, bn_op1, bn_op2, bn_n, context))
		goto err3;

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, result))
		goto err3;

err3:
	BN_CTX_free(context);
err2:
	BN_clear_free(bn_n);
	BN_clear_free(bn_op2);
	BN_clear_free(bn_op1);
	BN_clear_free(result);
err1:
	return;
}

void TEE_BigIntMulMod(TEE_BigInt *dest, TEE_BigInt *op1,
		      TEE_BigInt *op2, TEE_BigInt *n)
{
	BIGNUM *result;
	BIGNUM *bn_op1;
	BIGNUM *bn_op2;
	BIGNUM *bn_n;
	BN_CTX *context;

	/* Check parameters */
	if (dest == NULL || op1 == NULL || op2 == NULL || n == NULL)
		goto err1;

	/* Allocate BIGNUMs */
	result = BN_new();
	bn_op1 = AllocAndConvert(op1);
	bn_op2 = AllocAndConvert(op2);
	bn_n = AllocAndConvert(n);
	if (result == NULL || bn_op1 == NULL || bn_op2 == NULL || bn_n == NULL)
		goto err2;

	/* Create context for operation */
	context = BN_CTX_new();
	if (!context)
		goto err2;

	/* Do multiplication */
	if (!BN_mod_mul(result, bn_op1, bn_op2, bn_n, context))
		goto err3;

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, result))
		goto err3;

err3:
	BN_CTX_free(context);
err2:
	BN_clear_free(bn_n);
	BN_clear_free(bn_op2);
	BN_clear_free(bn_op1);
	BN_clear_free(result);
err1:
	return;
}

void TEE_BigIntSquareMod(TEE_BigInt *dest, TEE_BigInt *op, TEE_BigInt *n)
{
	BIGNUM *result;
	BIGNUM *bn_op;
	BIGNUM *bn_n;
	BN_CTX *context;

	/* Check parameters */
	if (dest == NULL || op == NULL || n == NULL)
		goto err1;

	/* Allocate BIGNUMs */
	result = BN_new();
	bn_op = AllocAndConvert(op);
	bn_n = AllocAndConvert(n);
	if (result == NULL || bn_op == NULL || bn_n == NULL)
		goto err2;

	/* Create context for operation */
	context = BN_CTX_new();
	if (!context)
		goto err2;

	/* Take square */
	if (!BN_mod_sqr(result, bn_op, bn_n, context))
		goto err3;

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, result))
		goto err3;

err3:
	BN_CTX_free(context);
err2:
	BN_clear_free(bn_n);
	BN_clear_free(bn_op);
	BN_clear_free(result);
err1:
	return;
}

void TEE_BigIntInvMod(TEE_BigInt *dest, TEE_BigInt *op, TEE_BigInt *n)
{
	BIGNUM *result;
	BIGNUM *bn_op;
	BIGNUM *bn_n;
	BN_CTX *context;

	/* Check parameters */
	if (dest == NULL || op == NULL || n == NULL)
		goto err1;

	/* Allocate BIGNUMs */
	result = BN_new();
	bn_op = AllocAndConvert(op);
	bn_n = AllocAndConvert(n);
	if (result == NULL || bn_op == NULL || bn_n == NULL)
		goto err2;

	/* Create context for operation */
	context = BN_CTX_new();
	if (!context)
		goto err2;

	/* Take inverse mod */
	if (!BN_mod_inverse(result, bn_op, bn_n, context)) {
		uint32_t err = ERR_get_error();
		printf("Error while calculating inverse mod: %i", err);
		goto err3;
	}

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, result))
		goto err3;

err3:
	BN_CTX_free(context);
err2:
	BN_clear_free(bn_n);
	BN_clear_free(bn_op);
	BN_clear_free(result);
err1:
	return;
}

/* Other Arithmetic Operations */
bool TEE_BigIntRelativePrime(TEE_BigInt *op1, TEE_BigInt *op2)
{
	bool ret = false;
	BIGNUM *result;
	BIGNUM *bn_op1;
	BIGNUM *bn_op2;
	BN_CTX *context;

	/* Check parameters */
	if (op1 == NULL || op2 == NULL)
		goto err1;

	/* Allocate BIGNUMs */
	result = BN_new();
	bn_op1 = AllocAndConvert(op1);
	bn_op2 = AllocAndConvert(op2);
	if (result == NULL || bn_op1 == NULL || bn_op2 == NULL)
		goto err2;

	/* Create context for operation */
	context = BN_CTX_new();
	if (!context)
		goto err2;

	/* Calculate gcd */
	if (!BN_gcd(result, bn_op1, bn_op2, context))
		goto err3;

	/* Return value is true if gcd(op1, op2) == 1 */
	ret = BN_is_one(result) ? true : false;

err3:
	BN_CTX_free(context);
err2:
	BN_clear_free(bn_op2);
	BN_clear_free(bn_op1);
	BN_clear_free(result);
err1:
	return ret;
}

static TEE_Result _egcd_iteration(BIGNUM *a, BIGNUM *a1, BIGNUM *q, BIGNUM *temp, BN_CTX *context)
{
	/* a, a1 = a1, a - q * a1 */

	BN_swap(temp, a);
	BN_swap(a, a1);

	/* a has old a1 */
	if (!BN_mul(a1, q, a, context))
		return TEE_ERROR_GENERIC;

	if (!BN_sub(a1, temp, a1))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

void TEE_BigIntComputeExtendedGcd(TEE_BigInt *gcd,
				  TEE_BigInt *u,
				  TEE_BigInt *v,
				  TEE_BigInt *op1,
				  TEE_BigInt *op2)
{
	BIGNUM *bn_u;
	BIGNUM *bn_v;
	BIGNUM *bn_g;
	BIGNUM *bn_u1;
	BIGNUM *bn_v1;
	BIGNUM *bn_g1;
	BIGNUM *bn_q;
	BIGNUM *bn_temp;
	BN_CTX *context;

	/* Check parameters */
	if (gcd == NULL || op1 == NULL || op2 == NULL)
		goto err1;

	/* BIGNUMs for algorithm */
	bn_u = BN_new();
	bn_v = BN_new();
	bn_g = AllocAndConvert(op1);
	bn_u1 = BN_new();
	bn_v1 = BN_new();
	bn_g1 = AllocAndConvert(op2);
	bn_q = BN_new();
	bn_temp = BN_new();

	if (bn_u == NULL || bn_v == NULL || bn_g == NULL ||
	    bn_u1 == NULL || bn_v1 == NULL || bn_g1 == NULL ||
	    bn_q == NULL || bn_temp == NULL)
		goto err2;

	/* Create context for operations */
	context = BN_CTX_new();
	if (!context)
		goto err2;

	/* The actual egcd algorithm starts here */
	/* u, u1 = 1, 0 */
	/* v, v1 = 0, 1 */
	BN_one(bn_u);
	BN_zero(bn_u1);
	BN_zero(bn_v);
	BN_one(bn_v1);

	while (!BN_is_zero(bn_g1)) {
		/* q = g / g1 */
		if (!BN_div(bn_q, NULL, bn_g, bn_g1, context))
			goto err3;

		if (_egcd_iteration(bn_u, bn_u1, bn_q, bn_temp, context) != TEE_SUCCESS ||
		    _egcd_iteration(bn_v, bn_v1, bn_q, bn_temp, context) != TEE_SUCCESS ||
		    _egcd_iteration(bn_g, bn_g1, bn_q, bn_temp, context) != TEE_SUCCESS)
			goto err3;
	}

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(gcd, bn_g))
		goto err3;

	if (u != NULL)
		if (BNToBigInt(u, bn_u))
			goto err3;

	if (v != NULL)
		if (BNToBigInt(v, bn_v))
			goto err3;

err3:
	BN_CTX_free(context);
err2:
	BN_clear_free(bn_temp);
	BN_clear_free(bn_q);
	BN_clear_free(bn_u);
	BN_clear_free(bn_v);
	BN_clear_free(bn_g);
	BN_clear_free(bn_u1);
	BN_clear_free(bn_v1);
	BN_clear_free(bn_g1);
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
	BIGNUM *bn_op = AllocAndConvert(op);
	if (!bn_op)
		goto err1;

	/* Create context for operation */
	BN_CTX *context = BN_CTX_new();
	if (!context)
		goto err2;

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
	/* Check parameters */
	if (dest == NULL || src == NULL || n == NULL || context == NULL)
		return;

	struct FMMContext *fmm = (struct FMMContext *)context;

	/* Check if magic is ok */
	if (FMM_context_magic != fmm->magic)
		return;

	/* Check if modulus is same than when initializing FMM context */
	if (TEE_BigIntCmp(fmm->modulus, n) != 0)
		return;

	/* Figure out length of TEE_BigInt */
	const size_t src_len = (GetHeader(src)->allocated_u32s * sizeof(uint32_t)) +
			       sizeof(struct TEE_BigInt_InternalHeader);

	memcpy(dest, src, src_len);

	return;
}

void TEE_BigIntConvertFromFMM(TEE_BigInt *dest, TEE_BigIntFMM *src,
			      TEE_BigInt *n, TEE_BigIntFMMContext *context)
{
	/* Check parameters */
	if (dest == NULL || src == NULL || n == NULL || context == NULL)
		return;

	struct FMMContext *fmm = (struct FMMContext *)context;

	/* Check if magic is ok */
	if (FMM_context_magic != fmm->magic)
		return;

	/* Check if modulus is same than when initializing FMM context */
	if (TEE_BigIntCmp(fmm->modulus, n) != 0)
		return;

	/* Figure out length of TEE_BigInt */
	const size_t src_len = (GetHeader(src)->allocated_u32s * sizeof(uint32_t)) +
			       sizeof(struct TEE_BigInt_InternalHeader);

	memcpy(dest, src, src_len);

	return;
}

void TEE_BigIntComputeFMM(TEE_BigIntFMM *dest, TEE_BigIntFMM *op1,
			  TEE_BigIntFMM *op2, TEE_BigInt *n,
			  TEE_BigIntFMMContext *context)
{
	/* Check parameters */
	if (dest == NULL || op1 == NULL || op2 == NULL
			 || n == NULL || context == NULL)
		return;

	struct FMMContext *fmm = (struct FMMContext *)context;

	/* Check if magic is ok */
	if (FMM_context_magic != fmm->magic)
		return;

	/* Check if modulus is same than when initializing FMM context */
	if (TEE_BigIntCmp(fmm->modulus, n) != 0)
		return;

	return TEE_BigIntMulMod(dest, op1, op2, n);
}

