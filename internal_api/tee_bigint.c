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

#include <mbedtls/bignum.h>

#include <openssl/bn.h>
#include <openssl/err.h>

/* For endianness functions */
#include <arpa/inet.h>

#include <string.h>
#include <assert.h>

/* Internal header for BigInt numbers */
struct TEE_BigInt_InternalHeader {
	uint32_t allocated; /* Size of allocated area not including this header */
	uint16_t rsvd1;
	int8_t flags; /* Currently only used to indicate negative sign */
	uint8_t rsvd2;
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

/**
 * @brief BigIntToMPI Convert the TEE_BigInt into a usable MPI struct
 * @param dst The MPI struct to populate
 * @param src The BigInt to convert
 */
static void BigIntToMPI(mbedtls_mpi *dst, TEE_BigInt *src)
{
	struct TEE_BigInt_InternalHeader *header;

	/* Check parameters */
	if (dst == NULL || src == NULL) {
		OT_LOG(LOG_ERR, "Internal error: Bad parameters for BigIntToBN");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	header = GetHeader(src);

	if (mbedtls_mpi_read_binary(dst, GetData(src), header->allocated)) {
		OT_LOG(LOG_ERR, "BigInt -> MPI conversion failed");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	dst->s = header->flags;
}

/**
 * @brief MPIToBigInt convert from mBed format to TEE_BigInt
 * @param dest output (must be large enough to hold the binary representation)
 * @param num input num
 * @return 0 on success, -1 if insufficent space
 */
static int32_t MPIToBigInt(TEE_BigInt *dest, const mbedtls_mpi *num)
{
	struct TEE_BigInt_InternalHeader *header;

	/* Check parameters */
	if (dest == NULL || num == NULL) {
		OT_LOG(LOG_ERR, "Internal Error: Null parameters");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	header = GetHeader(dest);

	if (mbedtls_mpi_write_binary(num, GetData(dest), header->allocated)) {
		OT_LOG(LOG_ERR, "mbedtls_mpi representation is too large (%zu)"
				"to fit in TEE_BigInt (%u)\n",
		       mbedtls_mpi_size(num), header->allocated);
		return -1;
	}

	header->flags = (int8_t)num->s;

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
	/* Check parameters */
	if (bigInt == NULL || len == 0)
		return;

	/* Fill the memory area with zeros */
	memset(bigInt, 0, len * sizeof(uint32_t));

	/* Store length to header in the beginning of the array */
	GetHeader(bigInt)->allocated = len * sizeof(uint32_t) -
				       sizeof(struct TEE_BigInt_InternalHeader);
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
	mbedtls_mpi num;
	TEE_Result ret = TEE_SUCCESS;

	/* Check parameters */
	if (dest == NULL || buffer == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* setup the mpi struct */
	mbedtls_mpi_init(&num);

	/* Convert "octet" string to BIGNUM */
	if (mbedtls_mpi_read_binary(&num, buffer, bufferLen)) {
		OT_LOG(LOG_ERR, "Internal error: mbedtls_mpi_read_binary call failed");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Set the sign for read value */
	num.s = (sign < 0) ? -1 : 1;

	if (MPIToBigInt(dest, &num))
		ret = TEE_ERROR_OUT_OF_MEMORY;

	mbedtls_mpi_free(&num);

	return ret;
}

TEE_Result TEE_BigIntConvertToOctetString(void *buffer,
					  size_t bufferLen,
					  TEE_BigInt *bigInt)
{
	mbedtls_mpi num;
	TEE_Result ret = TEE_SUCCESS;

	/* Check parameters */
	if (buffer == NULL || bigInt == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	mbedtls_mpi_init(&num);

	BigIntToMPI(&num, bigInt);

	if (mbedtls_mpi_write_binary(&num, (unsigned char *)buffer, bufferLen)) {
		OT_LOG(LOG_ERR, "Insufficent buffer size");
		ret = TEE_ERROR_SHORT_BUFFER;
	}

	mbedtls_mpi_free(&num);

	return ret;
}

void TEE_BigIntConvertFromS32(TEE_BigInt *dest, int32_t shortVal)
{
	mbedtls_mpi num;

	/* Check parameters */
	if (dest == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	mbedtls_mpi_init(&num);

	if (mbedtls_mpi_lset(&num, shortVal)) {
		OT_LOG(LOG_ERR, "Internal error: mbedtls_mpi_lset call failed");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	if (MPIToBigInt(dest, &num))
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);

	mbedtls_mpi_free(&num);
}

TEE_Result TEE_BigIntConvertToS32(int32_t *dest, TEE_BigInt *src)
{
	mbedtls_mpi num;

	/* Check parameters */
	if (dest == NULL || src == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	mbedtls_mpi_init(&num);

	BigIntToMPI(&num, src);

	/* TODO : Implement this to extract the correct 4 bytes from num.P !!!! */
	*dest = 0;

	mbedtls_mpi_free(&num);

	return TEE_SUCCESS;
}

/* Logical Operations */
int32_t TEE_BigIntCmp(TEE_BigInt *op1, TEE_BigInt *op2)
{
	int32_t ret;
	mbedtls_mpi X;
	mbedtls_mpi Y;

	/* Check parameters */
	if (op1 == NULL || op2 == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	mbedtls_mpi_init(&X);
	mbedtls_mpi_init(&Y);

	BigIntToMPI(&X, op1);
	BigIntToMPI(&Y, op2);

	ret = mbedtls_mpi_cmp_mpi(&X, &Y);

	mbedtls_mpi_free(&X);
	mbedtls_mpi_free(&Y);

	return ret;
}

int32_t TEE_BigIntCmpS32(TEE_BigInt *op1, int32_t shortVal)
{
	int32_t ret;
	mbedtls_mpi X;

	/* Check parameters */
	if (op1 == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	mbedtls_mpi_init(&X);
	BigIntToMPI(&X, op1);

	ret = mbedtls_mpi_cmp_int(&X, shortVal);
	mbedtls_mpi_free(&X);

	return ret;
}

void TEE_BigIntShiftRight(TEE_BigInt *dest, TEE_BigInt *op, size_t bits)
{
	mbedtls_mpi out;
	mbedtls_mpi in;

	/* Check parameters */
	if (dest == NULL || op == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	mbedtls_mpi_init(&out);
	mbedtls_mpi_init(&in);

	if (mbedtls_mpi_copy(&out, &in)) {
		OT_LOG(LOG_ERR, "Failed to copy, out of memory");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	if (mbedtls_mpi_shift_r(&out, bits)) {
		OT_LOG(LOG_ERR, "Failed to right shift, out of memory");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	if (MPIToBigInt(dest, &out))
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);

	mbedtls_mpi_free(&out);
	mbedtls_mpi_free(&in);

	return;
}

bool TEE_BigIntGetBit(TEE_BigInt *src, uint32_t bitIndex)
{
	bool ret;
	mbedtls_mpi num;

	/* Check parameters */
	if (src == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	mbedtls_mpi_init(&num);
	BigIntToMPI(&num, src);

	ret = mbedtls_mpi_get_bit(&num, bitIndex);

	mbedtls_mpi_free(&num);

	return ret;
}

uint32_t TEE_BigIntGetBitCount(TEE_BigInt *src)
{
	uint32_t ret;
	mbedtls_mpi num;

	/* Check parameters */
	if (src == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	mbedtls_mpi_init(&num);
	BigIntToMPI(&num, src);

	ret = mbedtls_mpi_bitlen(&num);

	mbedtls_mpi_free(&num);

	return ret;
}

/* Basic Arithmetic Operations */
void TEE_BigIntAdd(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2)
{
	mbedtls_mpi result;
	mbedtls_mpi left;
	mbedtls_mpi right;

	/* Check parameters */
	if (dest == NULL || op1 == NULL || op2 == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	mbedtls_mpi_init(&result);
	mbedtls_mpi_init(&left);
	mbedtls_mpi_init(&right);

	BigIntToMPI(&left, op1);
	BigIntToMPI(&right, op2);

	if (mbedtls_mpi_add_mpi(&result, &left, &right)) {
		OT_LOG(LOG_ERR, "Could not add MPI operands");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	if (MPIToBigInt(dest, &result))
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);

	mbedtls_mpi_free(&result);
	mbedtls_mpi_free(&left);
	mbedtls_mpi_free(&right);
}

void TEE_BigIntSub(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2)
{
	mbedtls_mpi result;
	mbedtls_mpi left;
	mbedtls_mpi right;

	/* Check parameters */
	if (dest == NULL || op1 == NULL || op2 == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	mbedtls_mpi_init(&result);
	mbedtls_mpi_init(&left);
	mbedtls_mpi_init(&right);

	BigIntToMPI(&left, op1);
	BigIntToMPI(&right, op2);

	if (mbedtls_mpi_sub_mpi(&result, &left, &right)) {
		OT_LOG(LOG_ERR, "Could not subtract MPI operands");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	if (MPIToBigInt(dest, &result))
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);

	mbedtls_mpi_free(&result);
	mbedtls_mpi_free(&left);
	mbedtls_mpi_free(&right);
}

void TEE_BigIntNeg(TEE_BigInt *dest, TEE_BigInt *op)
{
	mbedtls_mpi result;

	/* Check parameters */
	if (dest == NULL || op == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	mbedtls_mpi_init(&result);
	BigIntToMPI(&result, op);
	/* ensure a negative signedness */
	result.s = -1;

	if (MPIToBigInt(dest, &result))
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);

	mbedtls_mpi_free(&result);
}

void TEE_BigIntMul(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2)
{
	mbedtls_mpi result;
	mbedtls_mpi left;
	mbedtls_mpi right;

	/* Check parameters */
	if (dest == NULL || op1 == NULL || op2 == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	mbedtls_mpi_init(&result);
	mbedtls_mpi_init(&left);
	mbedtls_mpi_init(&right);

	BigIntToMPI(&left, op1);
	BigIntToMPI(&right, op2);

	if (mbedtls_mpi_mul_mpi(&result, &left, &right)) {
		OT_LOG(LOG_ERR, "Could not allocate MPI for operands");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	if (MPIToBigInt(dest, &result))
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);

	mbedtls_mpi_free(&result);
	mbedtls_mpi_free(&left);
	mbedtls_mpi_free(&right);
}

void TEE_BigIntSquare(TEE_BigInt *dest, TEE_BigInt *op)
{
	TEE_BigIntMul(dest, op, op);
}

void TEE_BigIntDiv(TEE_BigInt *dest_q, TEE_BigInt *dest_r,
		   TEE_BigInt *op1, TEE_BigInt *op2)
{
	mbedtls_mpi Q;
	mbedtls_mpi R;
	mbedtls_mpi left;
	mbedtls_mpi right;
	int ret;

	/* Check parameters */
	if (dest_q == NULL || dest_r == NULL || op1 == NULL || op2 == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	mbedtls_mpi_init(&Q);
	mbedtls_mpi_init(&R);
	mbedtls_mpi_init(&left);
	mbedtls_mpi_init(&right);

	BigIntToMPI(&left, op1);
	BigIntToMPI(&right, op2);

	ret = mbedtls_mpi_div_mpi(&Q, &R, &left, &right);
	if (ret == MBEDTLS_ERR_MPI_ALLOC_FAILED) {
		OT_LOG(LOG_ERR, "Could not allocate MPI for operands");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	} else if (ret == MBEDTLS_ERR_MPI_DIVISION_BY_ZERO) {
		OT_LOG(LOG_ERR, "Divide by Zero Error");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (MPIToBigInt(dest_q, &Q))
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	if (MPIToBigInt(dest_r, &R))
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);

	mbedtls_mpi_free(&Q);
	mbedtls_mpi_free(&R);
	mbedtls_mpi_free(&left);
	mbedtls_mpi_free(&right);
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
	src_len = GetHeader(src)->allocated + sizeof(struct TEE_BigInt_InternalHeader);

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
	src_len = GetHeader(src)->allocated + sizeof(struct TEE_BigInt_InternalHeader);

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

