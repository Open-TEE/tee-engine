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

#include "tee_data_types.h"

/* Data types */
typedef uint32_t TEE_BigInt;
typedef uint32_t TEE_BigIntFMMContext;
typedef uint32_t TEE_BigIntFMM;

#define TEE_BIGINT_INTERNAL_HEADER_SIZE (sizeof(uint32_t) * 2)

#define TEE_BIGINT_FLAGS_NEGATIVE 1

/* Memory allocation and Size of Objects */
#define TEE_BigIntSizeInU32(n) ((((n) + 31) / 32) + \
		(TEE_BIGINT_INTERNAL_HEADER_SIZE / sizeof(uint32_t)))

size_t TEE_BigIntFMMContextSizeInU32(size_t modulusSizeInBits);

size_t TEE_BigIntFMMSizeInU32(size_t modulusSizeInBits);

/* Initialization Functions */
/***
 *  Initializes TEE_BigInt structure and sets the value to zero.
 *  @param bigInt Big integer to be initialized
 *  @param len Size of big integer as given by TEE_BigIntSizeInU32
 */
void TEE_BigIntInit(TEE_BigInt *bigInt, size_t len);

/***
 *  Initializes Fast Modular Multiplication context for given modulus.
 *  In this implementation FMM functions provide equal performance to
 *  regular multiplication.
 *  @param context Context to be initialized
 *  @param len Size of FMM context as given by TEE_BigIntFMMContextSizeInU32
 *  @param modulus Modulus to initalize FMM context for
 */
void TEE_BigIntInitFMMContext(TEE_BigIntFMMContext *context, size_t len,
			      TEE_BigInt *modulus);

/***
 * Initializes Fast Modular Multiplication big integer.
 * @param bigIntFMM FMM Big Integer
 * @param len Size of big integer as given by TEE_BigIntFMMSizeInU32
 */
void TEE_BigIntInitFMM(TEE_BigIntFMM *bigIntFMM, size_t len);

/* Converter Functions */

/***
 * Convert integer from binary byte order representation to TEE_BigInt
 * @param dest Destination big integer
 * @param buffer Source buffer
 * @param bufferLen Length of source buffer
 * @param sign Sign of the value
 * @return TEE_SUCCESS if successful,
 *         TEE_ERROR_OVERFLOW if the destination is too small
 */
TEE_Result TEE_BigIntConvertFromOctetString(TEE_BigInt *dest, uint8_t *buffer,
					    size_t bufferLen, int32_t sign);

/***
 * Convert integer from TEE_BigInt to binary byte order representation
 * @param buffer Destination buffer
 * @param bufferLen Length of destination buffer
 * @param bigInt Source big integer
 * @return TEE_SUCCESS if successful,
 *         TEE_ERROR_SHORT_BUFFER is buffer is too short
 */
TEE_Result TEE_BigIntConvertToOctetString(void *buffer,
					  size_t bufferLen,
					  TEE_BigInt *bigInt);

/***
 * Convert integer from int32_t to TEE_BigInt
 * @param dest Destination big integer
 * @param shortVal Source integer
 */
void TEE_BigIntConvertFromS32(TEE_BigInt *dest, int32_t shortVal);

/***
 * Convert integer from TEE_BigInt to int32_t
 * @param dest Destination integer
 * @param src Source big integer
 * @return TEE_SUCCESS if successful,
 *         TEE_ERROR_OVERFLOW if integer does not fit into int32_t
 */
TEE_Result TEE_BigIntConvertToS32(int32_t *dest, TEE_BigInt *src);

/* Logical Operations */

/***
 * Compare too big integers
 * @param op1 First operand
 * @param op2 Second operand
 * @return Negative number if op1 < op2,
 *         0 if equal,
 *         Positive number if op1 > op2
 */
int32_t TEE_BigIntCmp(TEE_BigInt *op1, TEE_BigInt *op2);

/***
 * Compare big integer to int32_t
 * @param op1 First operand
 * @param shortVal Second operand
 * @return Negative number if op1 < shortVal,
 *         0 if equal,
 *         Positive number if op1 > shortVal
 */
int32_t TEE_BigIntCmpS32(TEE_BigInt *op1, int32_t shortVal);

/***
 * Shift big integer right
 * @param dest Destination big integer
 * @param op Operand to shift
 * @param bits Number of bits to shift
 */
void TEE_BigIntShiftRight(TEE_BigInt *dest, TEE_BigInt *op, size_t bits);

/***
 * Tells if bitIndex bit has been set in big integer
 * @param src Big integer to test bit from
 * @param bitindex Index of bit to test
 * @return true if the requested bit was set, false otherwise
 */
bool TEE_BigIntGetBit(TEE_BigInt *src, uint32_t bitIndex);

/***
 * Returns magnitude of big integer, which is the bits needed
 * to represent the number.
 * @param src Big integer
 * @return Magnitude of big integer
 */
uint32_t TEE_BigIntGetBitCount(TEE_BigInt *src);

/* Basic Arithmetic Operations */

/***
 * Adds two operands and puts the result to dest
 * @param dest Destination
 * @param op1 First operand
 * @param op2 Second operand
 */
void TEE_BigIntAdd(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2);

/***
 * Substracts two operands and puts the result to dest
 * @param dest Destination
 * @param op1 First operand
 * @param op2 Second operand
 */
void TEE_BigIntSub(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2);

/***
 * Negates operand and puts the result to dest
 * @param dest Destination
 * @param op Operand
 */
void TEE_BigIntNeg(TEE_BigInt *dest, TEE_BigInt *op);

/***
 * Multiplicates two operands and puts the result to dest
 * @param dest Destination
 * @param op1 First operand
 * @param op2 Second operand
 */
void TEE_BigIntMul(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2);

/***
 * Squares operand and puts the result to dest
 * @param dest Destination
 * @param op Operand
 */
void TEE_BigIntSquare(TEE_BigInt *dest, TEE_BigInt *op);

/***
 * Divides two operands and puts the quotient to dest_q and remainder to dest_r
 * @param dest_q Destination for quotient
 * @param dest_r Destination for remainder
 * @param op1 First operand
 * @param op2 Second operand
 */
void TEE_BigIntDiv(TEE_BigInt *dest_q, TEE_BigInt *dest_r,
		   TEE_BigInt *op1, TEE_BigInt *op2);

/* Modular Arithmetic Operations */

/***
 * Calculate modulus of op and n and put the the result to dest
 * @param dest Destination
 * @param op Operand
 * @param n Modulus
 */
void TEE_BigIntMod(TEE_BigInt *dest, TEE_BigInt *op, TEE_BigInt *n);

/***
 * Adds two operands and puts the result to dest with modulus n
 * @param dest Destination
 * @param op1 First operand
 * @param op2 Second operand
 * @param n Modulus
 */
void TEE_BigIntAddMod(TEE_BigInt *dest, TEE_BigInt *op1,
		      TEE_BigInt *op2, TEE_BigInt *n);

/***
 * Substracts two operands and puts the result to dest with modulus n
 * @param dest Destination
 * @param op1 First operand
 * @param op2 Second operand
 * @param n Modulus
 */
void TEE_BigIntSubMod(TEE_BigInt *dest, TEE_BigInt *op1,
		      TEE_BigInt *op2, TEE_BigInt *n);

/***
 * Multiplicates two operands and puts the result to dest with modulus n
 * @param dest Destination
 * @param op1 First operand
 * @param op2 Second operand
 * @param n Modulus
 */
void TEE_BigIntMulMod(TEE_BigInt *dest, TEE_BigInt *op1,
		      TEE_BigInt *op2, TEE_BigInt *n);

/***
 * Squares operand and puts the result to dest with modulus n
 * @param dest Destination
 * @param op Operand
 * @param n Modulus
 */
void TEE_BigIntSquareMod(TEE_BigInt *dest, TEE_BigInt *op, TEE_BigInt *n);

/***
 * Calculates inverse mod of operand and puts the result to dest
 * @param dest Destination
 * @param op Operand
 * @param n Modulus
 */
void TEE_BigIntInvMod(TEE_BigInt *dest, TEE_BigInt *op, TEE_BigInt *n);

/* Other Arithmetic Operations */

/***
 * Tells if operands are relative prime.
 * In other words, if gcd(op1, op2) == 1.
 * @param op1 First operand
 * @param op2 Second operand
 * @return true if gcd(op1, op2) == 1, false otherwise
 */
bool TEE_BigIntRelativePrime(TEE_BigInt *op1, TEE_BigInt *op2);

/***
 * Calculate extended gcd for two operands.
 * @param gcd Destination for gcd
 * @param u Destination for first coefficient
 * @param v Destination for second coefficient
 * @param op1 First operand
 * @param op2 Second operand
 */
void TEE_BigIntComputeExtendedGcd(TEE_BigInt *gcd, TEE_BigInt *u,
				  TEE_BigInt *v, TEE_BigInt *op1,
				  TEE_BigInt *op2);

/***
 * Performs a probabilistic primality test on op.
 * Tests that probability of op being composite is less than
 * 2^-confidencelevel.
 * @param op Operand
 * @param confidencelevel Sets probability for prime 2^-confidencelevel.
 *                        Must be at least 80, smaller values are ignored
 *                        and treated as 80.
 * @return 0 if op is composite,
 *         -1 if op is probable prime,
 *         this implementation never returns 1 which would mean
 *         guaranteed prime.
 */
int32_t TEE_BigIntIsProbablePrime(TEE_BigInt *op, uint32_t confidenceLevel);

/* Fast Modular Multiplication Operations */

/***
 * Convert big integer to FMM compatible representation
 * @param dest Destination FMM compatible big integer
 * @param src Source big integer
 * @param n Modulus to be used
 * @param context Initialized FMM context
 */
void TEE_BigIntConvertToFMM(TEE_BigIntFMM *dest, TEE_BigInt *src,
			    TEE_BigInt *n, TEE_BigIntFMMContext *context);

/***
 * Convert FMM compatible representation back to big integer
 * @param dest Destination big integer
 * @param src Source FMM compatible big integer
 * @param n Modulus to be used
 * @param context Initialized FMM context
 */
void TEE_BigIntConvertFromFMM(TEE_BigInt *dest, TEE_BigIntFMM *src,
			      TEE_BigInt *n, TEE_BigIntFMMContext *context);

/***
 * Compute modular multiplication with FMM context.
 * This implementation does not optimize for FMM but uses the same
 * algorithm than for regular multiplication.
 * @param dest Destination
 * @param op1 First operand
 * @param op2 Second operand
 * @param n Modulus to be used
 * @param context Initialized FMM context
 */
void TEE_BigIntComputeFMM(TEE_BigIntFMM *dest, TEE_BigIntFMM *op1,
			  TEE_BigIntFMM *op2, TEE_BigInt *n,
			  TEE_BigIntFMMContext *context);

#endif /* __TEE_BIGINT_H__ */
