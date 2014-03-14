import cffi
import os

ffi = cffi.FFI()

# cdefs i.e. the API visible to Python
# Since directives are not yet supported,
# copying definitions from public API here
ffi.cdef("""
/* Data types */
typedef uint32_t TEE_BigInt;
typedef uint32_t TEE_BigIntFMMContext;
typedef uint32_t TEE_BigIntFMM;
typedef uint32_t TEE_Result;

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

TEE_Result TEE_BigIntConvertToS32(int32_t *dest, TEE_BigInt *src);

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

/* Needed for testing, Python CFFI can't "call" macros directly */
size_t getBigIntSizeInU32(size_t n);
""")

internal_api_lib_path = os.path.abspath("../../gcc-debug/InternalApi")
api = ffi.verify("""
#include \"%s/../internal_api/tee_bigint.h\"

size_t getBigIntSizeInU32(size_t n)
{
    return TEE_BigIntSizeInU32(n);
}
""" % (os.getcwd()),
library_dirs = [internal_api_lib_path],
libraries = ['InternalApi'])
