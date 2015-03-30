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
#include "tee_panic.h"
#include "tee_logging.h"

#include <openssl/bn.h>
#include <openssl/err.h>

/* For endianness functions */
#include <arpa/inet.h>

#include <string.h>
#include <assert.h>

/* Internal header for BigInt numbers */
struct TEE_BigInt_InternalHeader {
	uint32_t bytes_used_by_representation; /* Amount of bytes used by
						  OpenSSL BIGNUM representation */
	uint16_t allocated_u32s; /* Size of allocated area in uin32_t's
				    (excluding size of this header) */
	uint8_t flags; /* Currently only used to indicate negative sign */
	uint8_t rsvd1;
};

/* Constant that tells if FMM context has been initialized. "FMM" in ascii */
static const uint32_t FMM_context_magic = 0x00464D4D;
struct FMMContext {
	uint32_t magic;
	size_t length;
	TEE_BigInt *modulus;
};

/* Functions related to internal implementation */
static inline struct TEE_BigInt_InternalHeader *GetHeader(TEE_BigInt *bigInt)
{
	return (struct TEE_BigInt_InternalHeader *)bigInt;
}

static inline unsigned char *GetData(TEE_BigInt *bigInt)
{
	return (unsigned char *)bigInt + sizeof(struct TEE_BigInt_InternalHeader);
}

/***
 * Convert from our representation to OpenSSL BIGNUM
 * @param dest Pointer to OpenSSL BIGNUM
 * @param src Pointer to TEE_BigInt representation
 * @return 0 on success, error code otherwise
 */
static int32_t BigIntToBN(BIGNUM *dest, TEE_BigInt *src)
{
	BIGNUM *ret;

	/* Check parameters */
	if (dest == NULL || src == NULL) {
		OT_LOG(LOG_ERR, "Internal error: Bad parameters for BigIntToBN");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Convert binary data to BIGNUM value */
	/* Returns same pointer than it takes, and null on error */
	ret = BN_bin2bn(GetData(src),
			GetHeader(src)->bytes_used_by_representation,
			dest);
	if (ret == NULL || ret != dest) {
		OT_LOG(LOG_ERR, "BigInt -> BN conversion failed");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	/* Set signedness of BIGNUM */
	BN_set_negative(ret, GetHeader(src)->flags & TEE_BIGINT_FLAGS_NEGATIVE);

	return 0;
}

/***
 * Internal convenience function to be used in beginning of functions.
 * Converts TEE_BigInt representation to OpenSSL BIGNUM.
 * Panics with TEE_ERROR_GENERIC if fails.
 * @param TEE_BigInt GlobalPlatform style
 * @return Pointer to BIGNUM
 */
static BIGNUM *AllocAndConvert(TEE_BigInt *src)
{
	BIGNUM *ret = BN_new();
	if (src == NULL || ret == NULL || BigIntToBN(ret, src)) {
		/* Fail */
		BN_clear_free(ret);
		OT_LOG(LOG_ERR, "Error in AllocAndConvert");
		TEE_Panic(TEE_ERROR_GENERIC);
	}
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
	struct TEE_BigInt_InternalHeader *header;
	size_t representation_length;

	/* Check parameters */
	if (dest == NULL || src == NULL) {
		OT_LOG(LOG_ERR, "Internal Error: Null parameters");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	/* Cast pointer to header */
	header = GetHeader(dest);
	representation_length = BN_num_bytes(src);

	/* Check if representation fits in given TEE_BigInt */
	if (header->allocated_u32s * sizeof(uint32_t) < representation_length) {
		OT_LOG(LOG_ERR,
		       "BigNum representation of %zu does not fit into %zu\n",
		       representation_length,
		       header->allocated_u32s * sizeof(uint32_t));
		return -1;
	}

	header->flags = BN_is_negative(src) ? TEE_BIGINT_FLAGS_NEGATIVE : 0;

	/* Clear data first */
	memset(GetData(dest), 0, header->allocated_u32s * sizeof(uint32_t));

	/* Convert BIGNUM value to binary data */
	written_length = BN_bn2bin(src, GetData(dest));
	if (written_length < 0 || (size_t) written_length != representation_length) {
		OT_LOG(LOG_ERR,
		       "Internal error: BN_bn2bin output doesn't match representation length");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	header->bytes_used_by_representation = written_length;

	return 0;
}

static void EGCDIteration(BIGNUM *a, BIGNUM *a1, BIGNUM *q, BIGNUM *temp, BN_CTX *context)
{
	/* a, a1 = a1, a - q * a1 */

	BN_swap(temp, a);
	BN_swap(a, a1);

	/* a has old a1 */
	if (!BN_mul(a1, q, a, context) || !BN_sub(a1, temp, a1)) {
		OT_LOG(LOG_ERR, "Internal error: BN_bin2bn call failed");
		TEE_Panic(TEE_ERROR_GENERIC);
	}
}

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

/* Initialization Functions */
void TEE_BigIntInit(TEE_BigInt *bigInt, size_t len)
{
	assert(TEE_BIGINT_INTERNAL_HEADER_SIZE == sizeof(struct TEE_BigInt_InternalHeader));

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
	struct FMMContext *fmm;

	if (context == NULL)
		return;

	fmm = (struct FMMContext *)context;

	fmm->magic = FMM_context_magic;
	fmm->length = len;
	fmm->modulus = modulus;
}

void TEE_BigIntInitFMM(TEE_BigIntFMM *bigIntFMM, size_t len)
{
	return TEE_BigIntInit((TEE_BigInt *)bigIntFMM, len);
}

/* Converter Functions */
TEE_Result TEE_BigIntConvertFromOctetString(TEE_BigInt *dest, uint8_t *buffer,
					    size_t bufferLen, int32_t sign)
{
	TEE_Result ret = TEE_ERROR_OVERFLOW;
	BIGNUM *num;

	/* Check parameters */
	if (dest == NULL || buffer == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	num = BN_new();
	if (num == NULL) {
		OT_LOG(LOG_ERR, "Unable to allocated BIGNUM");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Convert "octet" string to BIGNUM */
	if (!BN_bin2bn(buffer, bufferLen, num)) {
		OT_LOG(LOG_ERR, "Internal error: BN_bin2bn call failed");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	/* Set the sign for read value */
	BN_set_negative(num, sign != 0);

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, num))
		goto err;

	ret = TEE_SUCCESS;

err:
	BN_clear_free(num);
	return ret;
}

TEE_Result TEE_BigIntConvertToOctetString(void *buffer,
					  size_t bufferLen,
					  TEE_BigInt *bigInt)
{
	TEE_Result ret = TEE_ERROR_SHORT_BUFFER;
	BIGNUM *num;
	size_t length_of_str;

	/* Check parameters */
	if (buffer == NULL || bigInt == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Allocate BIGNUM */
	num = AllocAndConvert(bigInt);
	if (num == NULL) {
		OT_LOG(LOG_ERR, "Could not allocate BIGNUM for operands");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	length_of_str = BN_num_bytes(num);
	if (bufferLen < length_of_str + 1)
		goto err; /* Return TEE_ERROR_SHORT_BUFFER */

	memset(buffer, 0, bufferLen);

	/* Get string representation from BIGNUM API */
	if (BN_num_bytes(num) !=
	    BN_bn2bin(num,
		      &(((unsigned char *)buffer)[bufferLen - length_of_str]))) {
		OT_LOG(LOG_ERR, "Internal error: BN_bn2bin call failed");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	ret = TEE_SUCCESS;

err:
	BN_clear_free(num);
	return ret;
}

void TEE_BigIntConvertFromS32(TEE_BigInt *dest, int32_t shortVal)
{
	BIGNUM *bn_dest;

	/* Calculate absolute value of shortVal and change from host order to big endian */
	const uint32_t absVal = htonl(shortVal < 0 ? -shortVal : shortVal);

	/* Check parameters */
	if (dest == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	bn_dest = BN_bin2bn((uint8_t *)(&absVal), sizeof(uint32_t), NULL);
	if (bn_dest == NULL) {
		OT_LOG(LOG_ERR, "Internal error: BN_bin2bn call failed");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	/* Set the negative sign if needed */
	if (shortVal < 0)
		BN_set_negative(bn_dest, true);

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, bn_dest))
		TEE_Panic(TEE_ERROR_GENERIC);

	BN_clear_free(bn_dest);
	return;
}

TEE_Result TEE_BigIntConvertToS32(int32_t *dest, TEE_BigInt *src)
{
	TEE_Result ret = TEE_SUCCESS;
	BIGNUM *bn_src = NULL;

	/* Check parameters */
	if (dest == NULL || src == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Allocate BIGNUM */
	bn_src = AllocAndConvert(src);
	if (bn_src == NULL) {
		OT_LOG(LOG_ERR, "Could not allocate BIGNUM for operands");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	const size_t representation_length = BN_num_bytes(bn_src);
	if (representation_length == 0) {
		/* OpenSSL BigNum library uses repr. length 0 when value is 0 */
		*dest = 0;
	} else if (representation_length > 0 && representation_length <= sizeof(uint32_t)) {
		*dest = 0;
		if (!BN_bn2bin(bn_src,
			       (uint8_t *)dest + (sizeof(uint32_t) - representation_length))) {
			OT_LOG(LOG_ERR, "Error converting BIGNUM representation to int32");
			TEE_Panic(TEE_ERROR_GENERIC);
		}


		/* Change endianness from big endian to host order */
		/* Multiply with -1 if negative number */
		*dest = (ntohl(*dest) & (~(1 << 31))) * (BN_is_negative(bn_src) ? -1 : 1);
	} else {
		OT_LOG(LOG_ERR, "BigInt does not fit into int32_t");
		ret = TEE_ERROR_OVERFLOW;
	}

	BN_clear_free(bn_src);
	return ret;
}

/* Logical Operations */
int32_t TEE_BigIntCmp(TEE_BigInt *op1, TEE_BigInt *op2)
{
	int32_t ret;
	BIGNUM *bn_op1;
	BIGNUM *bn_op2;

	/* Check parameters */
	if (op1 == NULL || op2 == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Allocate BIGNUMs */
	bn_op1 = AllocAndConvert(op1);
	bn_op2 = AllocAndConvert(op2);
	if (bn_op1 == NULL || bn_op2 == NULL) {
		OT_LOG(LOG_ERR, "Could not allocate BIGNUM for operands");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Do the comparison */
	ret = BN_cmp(bn_op1, bn_op2);

	BN_clear_free(bn_op1);
	BN_clear_free(bn_op2);
	return ret;
}

int32_t TEE_BigIntCmpS32(TEE_BigInt *op1, int32_t shortVal)
{
	/* Statically allocate space for TEE_BigInt */
	TEE_BigInt op2[TEE_BigIntSizeInU32(32)];

	/* Check parameters */
	if (op1 == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	TEE_BigIntInit(op2, TEE_BigIntSizeInU32(32));

	/* Convert int32_t -> TEE_BigInt */
	TEE_BigIntConvertFromS32(op2, shortVal);

	return TEE_BigIntCmp(op1, op2);
}

void TEE_BigIntShiftRight(TEE_BigInt *dest, TEE_BigInt *op, size_t bits)
{
	BIGNUM *result;
	BIGNUM *bn_op;

	/* Check parameters */
	if (dest == NULL || op == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Allocate BIGNUMs */
	result = BN_new();
	bn_op = AllocAndConvert(op);
	if (result == NULL || bn_op == NULL) {
		OT_LOG(LOG_ERR, "Could not allocate BIGNUM for operands");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Do the right shift */
	if (!BN_rshift(result, bn_op, bits)) {
		OT_LOG(LOG_ERR, "Internal error: BN_rshift call failed");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, result))
		TEE_Panic(TEE_ERROR_GENERIC);

	BN_clear_free(bn_op);
	BN_clear_free(result);

	return;
}

bool TEE_BigIntGetBit(TEE_BigInt *src, uint32_t bitIndex)
{
	bool ret;
	BIGNUM *bn_src;

	/* Check parameters */
	if (src == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Allocate BIGNUM */
	bn_src = AllocAndConvert(src);
	if (bn_src == NULL) {
		OT_LOG(LOG_ERR, "Could not allocate BIGNUM for operands");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Check bit status using bignum api */
	ret = BN_is_bit_set(bn_src, bitIndex) ? true : false;

	BN_clear_free(bn_src);
	return ret;
}

uint32_t TEE_BigIntGetBitCount(TEE_BigInt *src)
{
	uint32_t ret;

	/* Check parameters */
	if (src == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Allocate BIGNUM */
	BIGNUM *bn_src = AllocAndConvert(src);
	if (bn_src == NULL) {
		OT_LOG(LOG_ERR, "Could not allocate BIGNUM for operands");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Calculate bits using bignum api */
	ret = (uint32_t) BN_num_bits(bn_src);

	BN_clear_free(bn_src);
	return ret;
}

/* Basic Arithmetic Operations */
void TEE_BigIntAdd(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2)
{
	BIGNUM *result;
	BIGNUM *bn_op1;
	BIGNUM *bn_op2;

	/* Check parameters */
	if (dest == NULL || op1 == NULL || op2 == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Allocate BIGNUMs */
	result = BN_new();
	bn_op1 = AllocAndConvert(op1);
	bn_op2 = AllocAndConvert(op2);
	if (result == NULL || bn_op1 == NULL || bn_op2 == NULL) {
		OT_LOG(LOG_ERR, "Could not allocate BIGNUM for operands");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Do adding */
	if (!BN_add(result, bn_op1, bn_op2)) {
		OT_LOG(LOG_ERR, "Internal error: BN_add call failed");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, result))
		TEE_Panic(TEE_ERROR_GENERIC);

	BN_clear_free(bn_op2);
	BN_clear_free(bn_op1);
	BN_clear_free(result);
	return;
}

void TEE_BigIntSub(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2)
{
	BIGNUM *result;
	BIGNUM *bn_op1;
	BIGNUM *bn_op2;

	/* Check parameters */
	if (dest == NULL || op1 == NULL || op2 == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Allocate BIGNUMs */
	result = BN_new();
	bn_op1 = AllocAndConvert(op1);
	bn_op2 = AllocAndConvert(op2);
	if (result == NULL || bn_op1 == NULL || bn_op2 == NULL) {
		OT_LOG(LOG_ERR, "Could not allocate BIGNUM for operands");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Do substraction */
	if (!BN_sub(result, bn_op1, bn_op2)) {
		OT_LOG(LOG_ERR, "Internal error: BN_sub call failed");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, result))
		TEE_Panic(TEE_ERROR_GENERIC);

	BN_clear_free(bn_op2);
	BN_clear_free(bn_op1);
	BN_clear_free(result);
	return;
}

void TEE_BigIntNeg(TEE_BigInt *dest, TEE_BigInt *op)
{
	BIGNUM *bn_op;

	/* Check parameters */
	if (dest == NULL || op == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Allocate BIGNUM */
	bn_op = AllocAndConvert(op);
	if (bn_op == NULL) {
		OT_LOG(LOG_ERR, "Could not allocate BIGNUM for operands");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Change sign */
	BN_set_negative(bn_op, !BN_is_negative(bn_op));

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, bn_op))
		TEE_Panic(TEE_ERROR_GENERIC);

	BN_clear_free(bn_op);
	return;
}

void TEE_BigIntMul(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2)
{
	BIGNUM *result;
	BIGNUM *bn_op1;
	BIGNUM *bn_op2;

	/* Check parameters */
	if (dest == NULL || op1 == NULL || op2 == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Allocate BIGNUMs */
	result = BN_new();
	bn_op1 = AllocAndConvert(op1);
	bn_op2 = AllocAndConvert(op2);
	if (result == NULL || bn_op1 == NULL || bn_op2 == NULL) {
		OT_LOG(LOG_ERR, "Could not allocate BIGNUM for operands");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Create context for multiplication */
	BN_CTX *context = BN_CTX_new();
	if (!context) {
		OT_LOG(LOG_ERR, "Could not initialize context with BN_CTX_new");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Do multiplication */
	if (!BN_mul(result, bn_op1, bn_op2, context)) {
		OT_LOG(LOG_ERR, "Internal error: BN_mul call failed");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, result))
		TEE_Panic(TEE_ERROR_GENERIC);

	BN_CTX_free(context);
	BN_clear_free(bn_op2);
	BN_clear_free(bn_op1);
	BN_clear_free(result);
	return;
}

void TEE_BigIntSquare(TEE_BigInt *dest, TEE_BigInt *op)
{
	BIGNUM *bn_op;

	/* Check parameters */
	if (dest == NULL || op == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Allocate BIGNUM */
	bn_op = AllocAndConvert(op);
	if (bn_op == NULL) {
		OT_LOG(LOG_ERR, "Could not allocate BIGNUM for operands");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Create context for squarification */
	BN_CTX *context = BN_CTX_new();
	if (!context) {
		OT_LOG(LOG_ERR, "Could not initialize context with BN_CTX_new");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Teke the square of op */
	if (!BN_sqr(bn_op, bn_op, context)) {
		OT_LOG(LOG_ERR, "Internal error: BN_sqr call failed");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, bn_op))
		TEE_Panic(TEE_ERROR_GENERIC);

	BN_CTX_free(context);
	BN_clear_free(bn_op);
	return;
}

void TEE_BigIntDiv(TEE_BigInt *dest_q, TEE_BigInt *dest_r,
		   TEE_BigInt *op1, TEE_BigInt *op2)
{
	BIGNUM *div;
	BIGNUM *rem;
	BIGNUM *bn_op1;
	BIGNUM *bn_op2;

	/* Check parameters */
	if (dest_q == NULL || dest_r == NULL || op1 == NULL || op2 == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Allocate BIGNUMs */
	div = BN_new();
	rem = BN_new();
	bn_op1 = AllocAndConvert(op1);
	bn_op2 = AllocAndConvert(op2);
	if (div == NULL || rem == NULL || bn_op1 == NULL || bn_op2 == NULL) {
		OT_LOG(LOG_ERR, "Could not allocate BIGNUM for operands");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Create context for division */
	BN_CTX *context = BN_CTX_new();
	if (!context) {
		OT_LOG(LOG_ERR, "Could not initialize context with BN_CTX_new");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Do the division */
	if (!BN_div(div, rem, bn_op1, bn_op2, context)) {
		OT_LOG(LOG_ERR, "Internal error: BN_div call failed");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest_q, div))
		TEE_Panic(TEE_ERROR_GENERIC);

	if (BNToBigInt(dest_r, rem))
		TEE_Panic(TEE_ERROR_GENERIC);

	BN_CTX_free(context);
	BN_clear_free(bn_op2);
	BN_clear_free(bn_op1);
	BN_clear_free(rem);
	BN_clear_free(div);
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
	if (dest == NULL || op == NULL || n == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Allocate BIGNUMs */
	result = BN_new();
	bn_op = AllocAndConvert(op);
	bn_n = AllocAndConvert(n);
	if (result == NULL || bn_op == NULL || bn_n == NULL) {
		OT_LOG(LOG_ERR, "Could not allocate BIGNUM for operands");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Create context for operation */
	context = BN_CTX_new();
	if (!context) {
		OT_LOG(LOG_ERR, "Could not initialize context with BN_CTX_new");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Do mod */
	if (!BN_mod(result, bn_op, bn_n, context)) {
		OT_LOG(LOG_ERR, "Internal error: BN_mod call failed");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, result))
		TEE_Panic(TEE_ERROR_GENERIC);

	BN_CTX_free(context);
	BN_clear_free(bn_n);
	BN_clear_free(bn_op);
	BN_clear_free(result);
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
	if (dest == NULL || op1 == NULL || op2 == NULL || n == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Allocate BIGNUMs */
	result = BN_new();
	bn_op1 = AllocAndConvert(op1);
	bn_op2 = AllocAndConvert(op2);
	bn_n = AllocAndConvert(n);
	if (result == NULL || bn_op1 == NULL || bn_op2 == NULL || bn_n == NULL) {
		OT_LOG(LOG_ERR, "Could not allocate BIGNUM for operands");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Create context for operation */
	context = BN_CTX_new();
	if (!context) {
		OT_LOG(LOG_ERR, "Could not initialize context with BN_CTX_new");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Do adding */
	if (!BN_mod_add(result, bn_op1, bn_op2, bn_n, context)) {
		OT_LOG(LOG_ERR, "Internal error: BN_mod_add call failed");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, result))
		TEE_Panic(TEE_ERROR_GENERIC);

	BN_CTX_free(context);
	BN_clear_free(bn_n);
	BN_clear_free(bn_op2);
	BN_clear_free(bn_op1);
	BN_clear_free(result);
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
	if (dest == NULL || op1 == NULL || op2 == NULL || n == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Allocate BIGNUMs */
	result = BN_new();
	bn_op1 = AllocAndConvert(op1);
	bn_op2 = AllocAndConvert(op2);
	bn_n = AllocAndConvert(n);
	if (result == NULL || bn_op1 == NULL || bn_op2 == NULL || bn_n == NULL) {
		OT_LOG(LOG_ERR, "Could not allocate BIGNUM for operands");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Create context for operation */
	context = BN_CTX_new();
	if (!context) {
		OT_LOG(LOG_ERR, "Could not initialize context with BN_CTX_new");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Do substraction */
	if (!BN_mod_sub(result, bn_op1, bn_op2, bn_n, context)) {
		OT_LOG(LOG_ERR, "Internal error: BN_mod_sub call failed");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, result))
		TEE_Panic(TEE_ERROR_GENERIC);

	BN_CTX_free(context);
	BN_clear_free(bn_n);
	BN_clear_free(bn_op2);
	BN_clear_free(bn_op1);
	BN_clear_free(result);
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
	if (dest == NULL || op1 == NULL || op2 == NULL || n == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Allocate BIGNUMs */
	result = BN_new();
	bn_op1 = AllocAndConvert(op1);
	bn_op2 = AllocAndConvert(op2);
	bn_n = AllocAndConvert(n);
	if (result == NULL || bn_op1 == NULL || bn_op2 == NULL || bn_n == NULL) {
		OT_LOG(LOG_ERR, "Could not allocate BIGNUM for operands");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Create context for operation */
	context = BN_CTX_new();
	if (!context) {
		OT_LOG(LOG_ERR, "Could not initialize context with BN_CTX_new");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Do multiplication */
	if (!BN_mod_mul(result, bn_op1, bn_op2, bn_n, context)) {
		OT_LOG(LOG_ERR, "Internal error: BN_mod_mul call failed");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, result))
		TEE_Panic(TEE_ERROR_GENERIC);

	BN_CTX_free(context);
	BN_clear_free(bn_n);
	BN_clear_free(bn_op2);
	BN_clear_free(bn_op1);
	BN_clear_free(result);
	return;
}

void TEE_BigIntSquareMod(TEE_BigInt *dest, TEE_BigInt *op, TEE_BigInt *n)
{
	BIGNUM *result;
	BIGNUM *bn_op;
	BIGNUM *bn_n;
	BN_CTX *context;

	/* Check parameters */
	if (dest == NULL || op == NULL || n == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Allocate BIGNUMs */
	result = BN_new();
	bn_op = AllocAndConvert(op);
	bn_n = AllocAndConvert(n);
	if (result == NULL || bn_op == NULL || bn_n == NULL) {
		OT_LOG(LOG_ERR, "Could not allocate BIGNUM for operands");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Create context for operation */
	context = BN_CTX_new();
	if (!context) {
		OT_LOG(LOG_ERR, "Could not initialize context with BN_CTX_new");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Take square */
	if (!BN_mod_sqr(result, bn_op, bn_n, context)) {
		OT_LOG(LOG_ERR, "Internal error: BN_mod_sqr call failed");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, result))
		TEE_Panic(TEE_ERROR_GENERIC);

	BN_CTX_free(context);
	BN_clear_free(bn_n);
	BN_clear_free(bn_op);
	BN_clear_free(result);
	return;
}

void TEE_BigIntInvMod(TEE_BigInt *dest, TEE_BigInt *op, TEE_BigInt *n)
{
	BIGNUM *result;
	BIGNUM *bn_op;
	BIGNUM *bn_n;
	BN_CTX *context;

	/* Check parameters */
	if (dest == NULL || op == NULL || n == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Allocate BIGNUMs */
	result = BN_new();
	bn_op = AllocAndConvert(op);
	bn_n = AllocAndConvert(n);
	if (result == NULL || bn_op == NULL || bn_n == NULL) {
		OT_LOG(LOG_ERR, "Could not allocate BIGNUM for operands");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Create context for operation */
	context = BN_CTX_new();
	if (!context) {
		OT_LOG(LOG_ERR, "Could not initialize context with BN_CTX_new");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Take inverse mod */
	if (!BN_mod_inverse(result, bn_op, bn_n, context)) {
		OT_LOG(LOG_ERR, "Error while calculating inverse mod: %ld", ERR_get_error());
		OT_LOG(LOG_ERR, "Internal error: BN_mod_inverse call failed");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(dest, result))
		TEE_Panic(TEE_ERROR_GENERIC);

	BN_CTX_free(context);
	BN_clear_free(bn_n);
	BN_clear_free(bn_op);
	BN_clear_free(result);
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
	if (op1 == NULL || op2 == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Allocate BIGNUMs */
	result = BN_new();
	bn_op1 = AllocAndConvert(op1);
	bn_op2 = AllocAndConvert(op2);
	if (result == NULL || bn_op1 == NULL || bn_op2 == NULL) {
		OT_LOG(LOG_ERR, "Could not allocate BIGNUM for operands");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Create context for operation */
	context = BN_CTX_new();
	if (!context) {
		OT_LOG(LOG_ERR, "Could not initialize context with BN_CTX_new");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Calculate gcd */
	if (!BN_gcd(result, bn_op1, bn_op2, context)) {
		OT_LOG(LOG_ERR, "Internal error: BN_gcd call failed");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	/* Return value is true if gcd(op1, op2) == 1 */
	ret = BN_is_one(result) ? true : false;

	BN_CTX_free(context);
	BN_clear_free(bn_op2);
	BN_clear_free(bn_op1);
	BN_clear_free(result);
	return ret;
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
	if (gcd == NULL || op1 == NULL || op2 == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

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
	    bn_q == NULL || bn_temp == NULL) {
		OT_LOG(LOG_ERR, "Could not allocate BIGNUM for operands");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Create context for operations */
	context = BN_CTX_new();
	if (!context) {
		OT_LOG(LOG_ERR, "Could not initialize context with BN_CTX_new");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* The actual egcd algorithm starts here */
	/* u, u1 = 1, 0 */
	/* v, v1 = 0, 1 */
	BN_one(bn_u);
	BN_zero(bn_u1);
	BN_zero(bn_v);
	BN_one(bn_v1);

	while (!BN_is_zero(bn_g1)) {
		/* q = g / g1 */
		if (!BN_div(bn_q, NULL, bn_g, bn_g1, context)) {
			OT_LOG(LOG_ERR, "Internal error: BN_div call failed");
			TEE_Panic(TEE_ERROR_GENERIC);
		}

		EGCDIteration(bn_u, bn_u1, bn_q, bn_temp, context);
		EGCDIteration(bn_v, bn_v1, bn_q, bn_temp, context);
		EGCDIteration(bn_g, bn_g1, bn_q, bn_temp, context);
	}

	/* Convert result BIGNUM -> TEE_BigInt */
	if (BNToBigInt(gcd, bn_g))
		TEE_Panic(TEE_ERROR_GENERIC);

	if (u != NULL)
		if (BNToBigInt(u, bn_u))
			TEE_Panic(TEE_ERROR_GENERIC);

	if (v != NULL)
		if (BNToBigInt(v, bn_v))
			TEE_Panic(TEE_ERROR_GENERIC);

	BN_CTX_free(context);
	BN_clear_free(bn_temp);
	BN_clear_free(bn_q);
	BN_clear_free(bn_u);
	BN_clear_free(bn_v);
	BN_clear_free(bn_g);
	BN_clear_free(bn_u1);
	BN_clear_free(bn_v1);
	BN_clear_free(bn_g1);
}

int32_t TEE_BigIntIsProbablePrime(TEE_BigInt *op, uint32_t confidenceLevel)
{
	int32_t ret;
	int32_t result;

	/* Values smaller than 80 will be treated as 80 */
	confidenceLevel = confidenceLevel < 80 ? 80 : confidenceLevel;

	/* Parameter check */
	if (op == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Allocate BIGNUM */
	BIGNUM *bn_op = AllocAndConvert(op);
	if (!bn_op) {
		OT_LOG(LOG_ERR, "Could not allocate BIGNUM for operands");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Create context for operation */
	BN_CTX *context = BN_CTX_new();
	if (!context) {
		OT_LOG(LOG_ERR, "Could not initialize context with BN_CTX_new");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* TODO: How to check for "guaranteed prime" */

	result = BN_is_prime_ex(bn_op, confidenceLevel, context, NULL);
	if (result == -1) {
		OT_LOG(LOG_ERR, "Internal error: BN_is_prime_ex call failed");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	ret = result == 1 ? -1 : 0;

	BN_CTX_free(context);
	BN_clear_free(bn_op);
	return ret;
}

/* Fast Modular Multiplication Operations */
void TEE_BigIntConvertToFMM(TEE_BigIntFMM *dest, TEE_BigInt *src,
			    TEE_BigInt *n, TEE_BigIntFMMContext *context)
{
	struct FMMContext *fmm;
	size_t src_len;

	/* Check parameters */
	if (dest == NULL || src == NULL || n == NULL || context == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	fmm = (struct FMMContext *)context;

	/* Check if magic is ok */
	if (FMM_context_magic != fmm->magic) {
		OT_LOG(LOG_ERR, "Context has not been initialized");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	/* Check if modulus is same than when initializing FMM context */
	if (TEE_BigIntCmp(fmm->modulus, n) != 0) {
		OT_LOG(LOG_ERR, "Modulus is different than when initializing FMM context");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	/* Figure out length of TEE_BigInt */
	src_len = (GetHeader(src)->allocated_u32s * sizeof(uint32_t)) +
		   sizeof(struct TEE_BigInt_InternalHeader);

	memcpy(dest, src, src_len);

	return;
}

void TEE_BigIntConvertFromFMM(TEE_BigInt *dest, TEE_BigIntFMM *src,
			      TEE_BigInt *n, TEE_BigIntFMMContext *context)
{
	struct FMMContext *fmm;
	size_t src_len;

	/* Check parameters */
	if (dest == NULL || src == NULL || n == NULL || context == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	fmm = (struct FMMContext *)context;

	/* Check if magic is ok */
	if (FMM_context_magic != fmm->magic) {
		OT_LOG(LOG_ERR, "Context has not been initialized");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	/* Check if modulus is same than when initializing FMM context */
	if (TEE_BigIntCmp(fmm->modulus, n) != 0) {
		OT_LOG(LOG_ERR, "Modulus is different than when initializing FMM context");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	/* Figure out length of TEE_BigInt */
	src_len = (GetHeader(src)->allocated_u32s * sizeof(uint32_t)) +
		   sizeof(struct TEE_BigInt_InternalHeader);

	memcpy(dest, src, src_len);

	return;
}

void TEE_BigIntComputeFMM(TEE_BigIntFMM *dest, TEE_BigIntFMM *op1,
			  TEE_BigIntFMM *op2, TEE_BigInt *n,
			  TEE_BigIntFMMContext *context)
{
	struct FMMContext *fmm;

	/* Check parameters */
	if (dest == NULL || op1 == NULL || op2 == NULL
			 || n == NULL || context == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	fmm = (struct FMMContext *)context;

	/* Check if magic is ok */
	if (FMM_context_magic != fmm->magic) {
		OT_LOG(LOG_ERR, "Context has not been initialized");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	/* Check if modulus is same than when initializing FMM context */
	if (TEE_BigIntCmp(fmm->modulus, n) != 0) {
		OT_LOG(LOG_ERR, "Modulus is different than when initializing FMM context");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	return TEE_BigIntMulMod(dest, op1, op2, n);
}

