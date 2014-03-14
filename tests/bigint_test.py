#!/usr/bin/env python2
# Unit tests for Arithmetical API

import cffi
import os
from bigint_ffi import api, ffi
import unittest
import random

bits = 512
length = api.getBigIntSizeInU32(bits)

class BasicArithmetic(unittest.TestCase):

    def setUp(self):
        # Allocate memory and initialize 3 bigint numbers
        self.bigint_dest = ffi.new("TEE_BigInt[]", length);
        self.bigint_a    = ffi.new("TEE_BigInt[]", length);
        self.bigint_b    = ffi.new("TEE_BigInt[]", length);

        api.TEE_BigIntInit(self.bigint_dest, length)
        api.TEE_BigIntInit(self.bigint_a, length)
        api.TEE_BigIntInit(self.bigint_b, length)

        self.int_dest = ffi.new("int32_t[]", 1)

    def test_arithmetic(self):
        for i in range(0, 1000):
            #a = random.randint(1, (2 ** bits) - 1)
            #b = random.randint(1, (2 ** bits) - 1)
            a = random.randint(1, (2 ** 31) - 1)
            b = random.randint(1, (2 ** 31) - 1)

            api.TEE_BigIntConvertFromS32(self.bigint_a, a);
            api.TEE_BigIntConvertFromS32(self.bigint_b, b);
            api.TEE_BigIntConvertToS32(self.int_dest, self.bigint_a);
            self.assertEqual(self.int_dest[0], a)

            api.TEE_BigIntAdd(self.bigint_dest, self.bigint_a, self.bigint_b)
            api.TEE_BigIntConvertToS32(self.int_dest, self.bigint_dest);

            self.assertEqual(self.int_dest[0], a + b)

            api.TEE_BigIntSub(self.bigint_dest, self.bigint_a, self.bigint_b)
            api.TEE_BigIntConvertToS32(self.int_dest, self.bigint_dest)

            self.assertEqual(self.int_dest[0], a - b)

            api.TEE_BigIntMul(self.bigint_dest, self.bigint_a, self.bigint_b)
            api.TEE_BigIntConvertToS32(self.int_dest, self.bigint_dest)

            self.assertEqual(self.int_dest[0], a * b)

if __name__ == '__main__':
    print "Main"

    unittest.main()

    cffi.verifier.cleanup_tmpdir()
