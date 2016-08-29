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
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

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

	dst->private_s = header->flags;
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
		OT_LOG(LOG_ERR, "mbedtls_mpi rep is too large (%zu) to fit in TEE_BigInt (%u)\n",
		       mbedtls_mpi_size(num), header->allocated);
		return -1;
	}

	header->flags = (int8_t)num->private_s;

	return 0;
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
	num.private_s = (sign < 0) ? -1 : 1;

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
	result.private_s = -1;

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
	mbedtls_mpi result;
	mbedtls_mpi mpi_op;
	mbedtls_mpi mpi_n;
	int ret;

	/* Check parameters */
	if (dest == NULL || op == NULL || n == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	mbedtls_mpi_init(&result);
	mbedtls_mpi_init(&mpi_op);
	mbedtls_mpi_init(&mpi_n);

	BigIntToMPI(&mpi_op, op);
	BigIntToMPI(&mpi_n, n);

	ret = mbedtls_mpi_mod_mpi(&result, &mpi_op, &mpi_n);
	if (ret == MBEDTLS_ERR_MPI_ALLOC_FAILED) {
		OT_LOG(LOG_ERR, "Could not allocate MPI for operands");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	} else if (ret == MBEDTLS_ERR_MPI_DIVISION_BY_ZERO) {
		OT_LOG(LOG_ERR, "Divide by Zero Error");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (ret == MBEDTLS_ERR_MPI_NEGATIVE_VALUE) {
		OT_LOG(LOG_ERR, "n == 0");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (MPIToBigInt(dest, &result))
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);

	mbedtls_mpi_free(&result);
	mbedtls_mpi_free(&mpi_op);
	mbedtls_mpi_free(&mpi_n);
}

void TEE_BigIntAddMod(TEE_BigInt *dest, TEE_BigInt *op1,
		      TEE_BigInt *op2, TEE_BigInt *n)
{
	TEE_BigIntAdd(dest, op1, op2);
	TEE_BigIntMod(dest, dest, n);
}

void TEE_BigIntSubMod(TEE_BigInt *dest, TEE_BigInt *op1,
		      TEE_BigInt *op2, TEE_BigInt *n)
{
	TEE_BigIntSub(dest, op1, op2);
	TEE_BigIntMod(dest, dest, n);
}

void TEE_BigIntMulMod(TEE_BigInt *dest, TEE_BigInt *op1,
		      TEE_BigInt *op2, TEE_BigInt *n)
{
	TEE_BigIntMul(dest, op1, op2);
	TEE_BigIntMod(dest, dest, n);
}

void TEE_BigIntSquareMod(TEE_BigInt *dest, TEE_BigInt *op, TEE_BigInt *n)
{
	TEE_BigIntSquare(dest, op);
	TEE_BigIntMod(dest, dest, n);
}

void TEE_BigIntInvMod(TEE_BigInt *dest, TEE_BigInt *op, TEE_BigInt *n)
{
	mbedtls_mpi result;
	mbedtls_mpi mpi_op;
	mbedtls_mpi mpi_n;
	int ret;

	/* Check parameters */
	if (dest == NULL || op == NULL || n == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	mbedtls_mpi_init(&result);
	mbedtls_mpi_init(&mpi_op);
	mbedtls_mpi_init(&mpi_n);

	BigIntToMPI(&mpi_op, op);
	BigIntToMPI(&mpi_n, n);

	ret = mbedtls_mpi_inv_mod(&result, &mpi_op, &mpi_n);
	if (ret == MBEDTLS_ERR_MPI_ALLOC_FAILED) {
		OT_LOG(LOG_ERR, "Could not allocate MPI for operands");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	} else if (ret == MBEDTLS_ERR_MPI_BAD_INPUT_DATA) {
		OT_LOG(LOG_ERR, "n is negative or Zero");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (ret == MBEDTLS_ERR_MPI_NOT_ACCEPTABLE) {
		OT_LOG(LOG_ERR, "op has no inverse mod n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (MPIToBigInt(dest, &result))
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);

	mbedtls_mpi_free(&result);
	mbedtls_mpi_free(&mpi_op);
	mbedtls_mpi_free(&mpi_n);
}

/* Other Arithmetic Operations */
bool TEE_BigIntRelativePrime(TEE_BigInt *op1, TEE_BigInt *op2)
{
	bool ret = false;
	mbedtls_mpi G;
	mbedtls_mpi mpi_op1;
	mbedtls_mpi mpi_op2;

	/* Check parameters */
	if (op1 == NULL || op2 == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	mbedtls_mpi_init(&G);
	mbedtls_mpi_init(&mpi_op1);
	mbedtls_mpi_init(&mpi_op2);

	BigIntToMPI(&mpi_op1, op1);
	BigIntToMPI(&mpi_op2, op2);

	/* calculate gcd(op1, op2) */
	if (mbedtls_mpi_gcd(&G, &mpi_op1, &mpi_op2)) {
		OT_LOG(LOG_ERR, "Could not allocate MPI for operands");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Return value is true if gcd(op1, op2) == 1 */
	if (mbedtls_mpi_cmp_int(&G, 1) == 0)
		ret = true;

	mbedtls_mpi_free(&G);
	mbedtls_mpi_free(&mpi_op1);
	mbedtls_mpi_free(&mpi_op2);

	return ret;
}

static void EGCDIteration(mbedtls_mpi *a, mbedtls_mpi *a1, mbedtls_mpi *q, mbedtls_mpi *temp)
{
	/* a, a1 = a1, a - q * a1 */

	mbedtls_mpi_swap(temp, a);
	mbedtls_mpi_swap(a, a1);

	/* a has old a1 */
	if (mbedtls_mpi_mul_mpi(a1, q, a) || mbedtls_mpi_sub_mpi(a1, temp, a1)) {
		OT_LOG(LOG_ERR, "Internal error: BN_bin2bn call failed");
		TEE_Panic(TEE_ERROR_GENERIC);
	}
}

void TEE_BigIntComputeExtendedGcd(TEE_BigInt *gcd,
				  TEE_BigInt *u,
				  TEE_BigInt *v,
				  TEE_BigInt *op1,
				  TEE_BigInt *op2)
{
	mbedtls_mpi mpi_gcd;
	mbedtls_mpi mpi_u;
	mbedtls_mpi mpi_v;
	mbedtls_mpi mpi_u1;
	mbedtls_mpi mpi_v1;
	mbedtls_mpi mpi_op1;
	mbedtls_mpi mpi_op2;
	mbedtls_mpi mpi_temp;
	mbedtls_mpi mpi_q;

	/* Check parameters */
	if (gcd == NULL || op1 == NULL || op2 == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	mbedtls_mpi_init(&mpi_gcd);
	mbedtls_mpi_init(&mpi_op1);
	mbedtls_mpi_init(&mpi_op2);

	BigIntToMPI(&mpi_op1, op1);
	BigIntToMPI(&mpi_op2, op2);


	if (u == NULL && v == NULL) {
		/* calculate gcd(op1, op2) */
		if (mbedtls_mpi_gcd(&mpi_gcd, &mpi_op1, &mpi_op2)) {
			OT_LOG(LOG_ERR, "Could not allocate MPI for operands");
			TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
		}

		goto gcd_only_out;
	}

	mbedtls_mpi_init(&mpi_u);
	mbedtls_mpi_init(&mpi_v);
	mbedtls_mpi_init(&mpi_u1);
	mbedtls_mpi_init(&mpi_v1);
	mbedtls_mpi_init(&mpi_temp);
	mbedtls_mpi_init(&mpi_q);

	/* The actual egcd algorithm starts here */
	/* u, u1 = 1, 0 */
	/* v, v1 = 0, 1 */
	if (mbedtls_mpi_lset(&mpi_u, 1) || mbedtls_mpi_lset(&mpi_u1, 0) ||
	    mbedtls_mpi_lset(&mpi_v, 0) || mbedtls_mpi_lset(&mpi_v1, 1)) {
		OT_LOG(LOG_ERR, "Could not allocate MPI for operands");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	while (mbedtls_mpi_cmp_int(&mpi_op2, 1) != 0) {
		/* q = g / g1 */
		if (mbedtls_mpi_div_mpi(&mpi_q, NULL, &mpi_op1, &mpi_op2)) {
			OT_LOG(LOG_ERR, "Internal error: BN_div call failed");
			TEE_Panic(TEE_ERROR_GENERIC);
		}

		EGCDIteration(&mpi_u, &mpi_u1, &mpi_q, &mpi_temp);
		EGCDIteration(&mpi_v, &mpi_v1, &mpi_q, &mpi_temp);
		EGCDIteration(&mpi_op1, &mpi_op2, &mpi_q, &mpi_temp);
	}

	/* lazy copy */
	if (mbedtls_mpi_copy(&mpi_gcd, &mpi_op1)) {
		OT_LOG(LOG_ERR, "Could not allocate MPI for operands");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	if (MPIToBigInt(u, &mpi_u))
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);

	if (MPIToBigInt(v, &mpi_v))
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);

	mbedtls_mpi_free(&mpi_u);
	mbedtls_mpi_free(&mpi_v);
	mbedtls_mpi_free(&mpi_u1);
	mbedtls_mpi_free(&mpi_v1);
	mbedtls_mpi_free(&mpi_temp);
	mbedtls_mpi_free(&mpi_q);

gcd_only_out:

	if (MPIToBigInt(gcd, &mpi_gcd))
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);

	mbedtls_mpi_free(&mpi_gcd);
	mbedtls_mpi_free(&mpi_op1);
	mbedtls_mpi_free(&mpi_op2);
}

int32_t TEE_BigIntIsProbablePrime(TEE_BigInt *op, uint32_t confidenceLevel)
{
	mbedtls_mpi mpi_op;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;

	int32_t ret;
	int32_t result = 0;

	int int_confidenceLevel;

	//Default is 80
	//mbedtls api: 2^(-2*rounds)
	//GP api       2^(-rounds)
	if (confidenceLevel == 0) {
		int_confidenceLevel = 40;
	} else {
		int_confidenceLevel = confidenceLevel/2;
		if (int_confidenceLevel < 40) {
			int_confidenceLevel = 40;
		}
	}

	/* Parameter check */
	if (op == NULL) {
		OT_LOG(LOG_ERR, "Bad parameters");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	mbedtls_mpi_init(&mpi_op);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);

	BigIntToMPI(&mpi_op, op);

	/* seed the random number generator */
	if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) {
		OT_LOG(LOG_ERR, "Entropy source failed");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	ret = mbedtls_mpi_is_prime_ext(&mpi_op, int_confidenceLevel, mbedtls_ctr_drbg_random, &ctr_drbg);
	if (ret == MBEDTLS_ERR_MPI_ALLOC_FAILED) {
		OT_LOG(LOG_ERR, "Could not allocate MPI for operands");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	} else if (ret == MBEDTLS_ERR_MPI_NOT_ACCEPTABLE) {
		/* we do not have a prime OP */
		result = 0;
	} else {
		/* we have a prime */
		result = 1;
	}

	mbedtls_mpi_free(&mpi_op);
	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);

	return result;
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
