#!/usr/bin/env python2
# Unit tests for Arithmetical API

import cffi
import os
from bigint_ffi import api, ffi

if __name__ == '__main__':
    print "Main"

    bits = 512
    length = api.getBigIntSizeInU32(bits)

    # Allocate memory for 3 x 512 bit numbers
    bn_dest = ffi.new("TEE_BigInt[]", length)
    bn_a    = ffi.new("TEE_BigInt[]", length)
    bn_b    = ffi.new("TEE_BigInt[]", length)

    api.TEE_BigIntInit(bn_dest, length)
    api.TEE_BigIntInit(bn_a, length)
    api.TEE_BigIntInit(bn_b, length)

    intdest = ffi.new("int32_t[]", 1)

    a = -512000
    b = -2560

    api.TEE_BigIntConvertFromS32(bn_a, a);
    api.TEE_BigIntConvertFromS32(bn_b, b);
    api.TEE_BigIntConvertToS32(intdest, bn_a);

    print(intdest[0])

    assert intdest[0] == a

    api.TEE_BigIntAdd(bn_dest, bn_a, bn_b)
    api.TEE_BigIntConvertToS32(intdest, bn_dest);

    print(intdest[0])

    assert intdest[0] == a + b

    api.TEE_BigIntSub(bn_dest, bn_a, bn_b)
    api.TEE_BigIntConvertToS32(intdest, bn_dest);

    print(intdest[0])

    assert intdest[0] == a - b

    api.TEE_BigIntMul(bn_dest, bn_a, bn_b)
    api.TEE_BigIntConvertToS32(intdest, bn_dest);

    print(intdest[0])

    assert intdest[0] == a * b

    cffi.verifier.cleanup_tmpdir()
