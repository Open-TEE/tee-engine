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

#ifndef __TEE_BIGINT_H__
#define __TEE_BIGINT_H__

#include "data_types.h"

/* Data types */
typedef uint32_t TEE_BigInt;
typedef uint32_t TEE_BigIntFMMContext;
typedef uint32_t TEE_BigIntFMM;

/* Internal header for BigInt numbers */
struct TEE_BigInt_InternalHeader {
	uint32_t length;
	/* TODO: Fix: Waste of whole 32 bits for indicating negative sign */
	uint32_t neg;
};

/* Memory allocation and Size of Objects */
#define TEE_BigIntSizeInU32(n) ((((n) + 31) / 32) + \
		(sizeof(struct TEE_BigInt_InternalHeader) / sizeof(uint32_t)))

size_t TEE_BigIntFMMContextSizeInU32(size_t modulusSizeInBits);

size_t TEE_BigIntFMMSizeInU32(size_t modulusSizeInBits);

/* Initialization Functions */
void TEE_BigIntInit(TEE_BigInt *bigInt, size_t len);

void TEE_BigIntInitFMMContext(TEE_BigIntFMMContext *context, size_t len,
			      TEE_BigInt *modulus);

void TEE_BigIntInitFMM(TEE_BigIntFMM *bigIntFMM, size_t len);

/* Converter Functions */
TEE_Result TEE_BigIntConvertFromOctetString(TEE_BigInt *dest, uint8_t *buffer,
					    size_t bufferLen, int32_t sign);

TEE_Result TEE_BigIntConvertToOctetString(void *buffer,
					  size_t bufferLen,
					  TEE_BigInt *bigInt);

void TEE_BigIntConvertFromS32(TEE_BigInt *dest, int32_t shortVal);

void TEE_BigIntConvertToS32(int32_t *dest, TEE_BigInt *src);

/* Logical Operations */
int32_t TEE_BigIntCmp(TEE_BigInt *op1, TEE_BigInt *op2);

int32_t TEE_BigIntCmpS32(TEE_BigInt *op1, int32_t shortVal);

void TEE_BigIntShiftRight(TEE_BigInt *dest, TEE_BigInt *op, size_t bits);

bool TEE_BigIntGetBit(TEE_BigInt *src, uint32_t bitIndex);

uint32_t TEE_BigIntGetBitCount(TEE_BigInt *src);

/* Basic Arithmetic Operations */
void TEE_BigIntAdd(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2);

void TEE_BigIntSub(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2);

void TEE_BigIntNeg(TEE_BigInt *dest, TEE_BigInt *op);

void TEE_BigIntMul(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2);

void TEE_BigIntSquare(TEE_BigInt *dest, TEE_BigInt *op);

void TEE_BigIntDiv(TEE_BigInt *dest_q, TEE_BigInt *dest_r,
		   TEE_BigInt *op1, TEE_BigInt *op2);

/* Modular Arithmetic Operations */
void TEE_BigIntMod(TEE_BigInt *dest, TEE_BigInt *op, TEE_BigInt *n);

void TEE_BigIntAddMod(TEE_BigInt *dest, TEE_BigInt *op1,
		      TEE_BigInt *op2, TEE_BigInt *n);

void TEE_BigIntSubMod(TEE_BigInt *dest, TEE_BigInt *op1,
		      TEE_BigInt *op2, TEE_BigInt *n);

void TEE_BigIntMulMod(TEE_BigInt *dest, TEE_BigInt *op1,
		      TEE_BigInt *op2, TEE_BigInt *n);

void TEE_BigIntSquareMod(TEE_BigInt *dest, TEE_BigInt *op, TEE_BigInt *n);

void TEE_BigIntInvMod(TEE_BigInt *dest, TEE_BigInt *op, TEE_BigInt *n);

/* Other Arithmetic Operations */
bool TEE_BigIntRelativePrime(TEE_BigInt *op1, TEE_BigInt *op2);

void TEE_BigIntComputeExtendedGcd(TEE_BigInt *gcd, TEE_BigInt *u,
				  TEE_BigInt *v, TEE_BigInt *op1,
				  TEE_BigInt *op2);

int32_t TEE_BigIntIsProbablePrime(TEE_BigInt *op, uint32_t confidenceLevel);

/* Fast Modular Multiplication Operations */
void TEE_BigIntConvertToFMM(TEE_BigIntFMM *dest, TEE_BigInt *src,
			    TEE_BigInt *n, TEE_BigIntFMMContext *context);

void TEE_BigIntConvertFromFMM(TEE_BigInt *dest, TEE_BigIntFMM *src,
			      TEE_BigInt *n, TEE_BigIntFMMContext *context);

void TEE_BigIntComputeFMM(TEE_BigIntFMM *dest, TEE_BigIntFMM *op1,
			  TEE_BigIntFMM *op2, TEE_BigInt *n,
			  TEE_BigIntFMMContext *context);

#endif /* __TEE_BIGINT_H__ */
