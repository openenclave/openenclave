// acos.testdata
// copyright (C) 2007  F. de Dinechin, Ch. Q. Lauter and V. Lefevre
// This file is part of crlibm and is distributed under the GNU Public Licence
// See file COPYING for details
// The following lines are either comments (beginning with a #)
// or give
//   1/ a rounding mode : RN|RU|RD|RZ (crlibm syntax) or  N|P|M|Z (libmcr syntax)
//   2/ The high and low hexadecimal halves of an input
//   3/ The high and low hexadecimal halves of the expected corresponding output
// Special cases
T(RN,                  0x0p+0,    0x1.921fb54442d18p+0,  -0x1.1a6264p-2, INEXACT) // +0 -> RN(Pi/2)
T(RN,                 -0x0p+0,    0x1.921fb54442d18p+0,  -0x1.1a6264p-2, INEXACT) // -0 -> RN(Pi/2)
T(RD,                  0x0p+0,    0x1.921fb54442d18p+0,  -0x1.1a6264p-2, INEXACT) // +0 -> RD(Pi/2)
T(RD,                 -0x0p+0,    0x1.921fb54442d18p+0,  -0x1.1a6264p-2, INEXACT) // -0 -> RD(Pi/2)
T(RZ,                  0x0p+0,    0x1.921fb54442d18p+0,  -0x1.1a6264p-2, INEXACT) // +0 -> RZ(Pi/2)
T(RZ,                 -0x0p+0,    0x1.921fb54442d18p+0,  -0x1.1a6264p-2, INEXACT) // -0 -> RZ(Pi/2)
T(RU,                  0x0p+0,    0x1.921fb54442d19p+0,   0x1.72cecep-1, INEXACT) // +0 -> RU(Pi/2)
T(RU,                 -0x0p+0,    0x1.921fb54442d19p+0,   0x1.72cecep-1, INEXACT) // -0 -> RU(Pi/2)
T(RN,                  0x1p+0,                  0x0p+0,          0x0p+0, 0) // +1 -> +0
T(RN,                 -0x1p+0,    0x1.921fb54442d18p+1,  -0x1.1a6264p-2, INEXACT) // -1 -> RN(Pi)
T(RD,                  0x1p+0,                  0x0p+0,          0x0p+0, 0) // +1 -> +0
T(RD,                 -0x1p+0,    0x1.921fb54442d18p+1,  -0x1.1a6264p-2, INEXACT) // -1 -> RN(Pi)
T(RZ,                  0x1p+0,                  0x0p+0,          0x0p+0, 0) // +1 -> +0
T(RZ,                 -0x1p+0,    0x1.921fb54442d18p+1,  -0x1.1a6264p-2, INEXACT) // -1 -> RN(Pi)
T(RU,                  0x1p+0,                  0x0p+0,          0x0p+0, 0) // +1 -> +0
T(RU,                 -0x1p+0,    0x1.921fb54442d19p+1,   0x1.72cecep-1, INEXACT) // -1 -> RN(Pi)
T(RN,    0x1.0000000000001p+0,                     nan,          0x0p+0, INVALID) // +1 + 1ulp -> NaN the first one
T(RN,   -0x1.0000000000001p+0,                     nan,          0x0p+0, INVALID) // -1 - 1ulp -> NaN the first one
T(RU,    0x1.0000000000001p+0,                     nan,          0x0p+0, INVALID) // +1 + 1ulp -> NaN the first one
T(RU,   -0x1.0000000000001p+0,                     nan,          0x0p+0, INVALID) // -1 - 1ulp -> NaN the first one
T(RD,    0x1.0000000000001p+0,                     nan,          0x0p+0, INVALID) // +1 + 1ulp -> NaN the first one
T(RD,   -0x1.0000000000001p+0,                     nan,          0x0p+0, INVALID) // -1 - 1ulp -> NaN the first one
T(RZ,    0x1.0000000000001p+0,                     nan,          0x0p+0, INVALID) // +1 + 1ulp -> NaN the first one
T(RZ,   -0x1.0000000000001p+0,                     nan,          0x0p+0, INVALID) // -1 - 1ulp -> NaN the first one
// Cases around the interval bounds in the implementation
// A VIRER: CA CORRESPOND PLUS A LA NOUVELLE IMPLEMENTATION
// SI ON VEUT LAISSER LES TESTS AUTOUR DES BORNES JE PEUX LES FOURNIR
T(RN,            0x1.7ae14p-3,    0x1.627d4e6aebaaap+0,   0x1.9f9ca8p-2, INEXACT) // BOUND 1
T(RN,            0x1.32e91p-2,    0x1.4432cc777bc6dp+0,  -0x1.0423a4p-2, INEXACT) // BOUND 2
T(RN,            0x1.9ca24p-2,    0x1.27f28a9778f27p+0,   0x1.1ddf52p-3, INEXACT) // BOUND 3
T(RN,            0x1.f90b3p-2,    0x1.0e160fb695be7p+0,   0x1.2efc7cp-2, INEXACT) // BOUND 4
T(RN,            0x1.23adcp-1,    0x1.ede9ba1492b14p-1,   0x1.25e28ep-4, INEXACT) // BOUND 5
T(RN,            0x1.4781dp-1,     0x1.c0e3bda3f6bdp-1,   0x1.788eaep-3, INEXACT) // BOUND 6
T(RN,            0x1.647bbp-1,    0x1.99ebe5a6febcep-1,  -0x1.b779aep-2, INEXACT) // BOUND 7
T(RN,            0x1.7bc81p-1,     0x1.785f9b11a0b2p-1,   0x1.539e24p-2, INEXACT) // BOUND 8
T(RN,            0x1.8f5c2p-1,    0x1.5a2dd58639a11p-1,   0x1.3f0332p-3, INEXACT) // BOUND 9
T(RN,    0x1.7ae1400000001p-3,    0x1.627d4e6aebaa9p+0,  -0x1.de23cap-2, INEXACT) // BOUND 1 + 1ulp
T(RN,    0x1.32e9100000001p-2,    0x1.4432cc777bc6dp+0,   0x1.064b66p-7, INEXACT) // BOUND 2 + 1ulp
T(RN,    0x1.9ca2400000001p-2,    0x1.27f28a9778f27p+0,   0x1.a6a6c4p-2, INEXACT) // BOUND 3 + 1ulp
T(RN,    0x1.f90b300000001p-2,    0x1.0e160fb695be6p+0,  -0x1.aabb2cp-2, INEXACT) // BOUND 4 + 1ulp
T(RN,    0x1.23adc00000001p-1,    0x1.ede9ba1492b13p-1,   0x1.276bb8p-2, INEXACT) // BOUND 5 + 1ulp
T(RN,    0x1.4781d00000001p-1,    0x1.c0e3bda3f6bcfp-1,   0x1.f07954p-2, INEXACT) // BOUND 6 + 1ulp
T(RN,    0x1.647bb00000001p-1,    0x1.99ebe5a6febcdp-1,  -0x1.270c3ap-5, INEXACT) // BOUND 7 + 1ulp
T(RN,    0x1.7bc8100000001p-1,    0x1.785f9b11a0b1ep-1,  -0x1.6b13c6p-3, INEXACT) // BOUND 8 + 1ulp
T(RN,    0x1.8f5c200000001p-1,    0x1.5a2dd58639a0fp-1,  -0x1.f84564p-3, INEXACT) // BOUND 9 + 1ulp
T(RN,    0x1.7ae13ffffffffp-3,    0x1.627d4e6aebaaap+0,   0x1.1d5d18p-2, INEXACT) // BOUND 1 - 1ulp
T(RN,    0x1.32e90ffffffffp-2,    0x1.4432cc777bc6ep+0,   0x1.ef865ep-2, INEXACT) // BOUND 2 - 1ulp
T(RN,    0x1.9ca23ffffffffp-2,    0x1.27f28a9778f27p+0,  -0x1.118ee4p-3, INEXACT) // BOUND 3 - 1ulp
T(RN,    0x1.f90b2ffffffffp-2,    0x1.0e160fb695be7p+0,   0x1.16848cp-7, INEXACT) // BOUND 4 - 1ulp
T(RN,    0x1.23adbffffffffp-1,    0x1.ede9ba1492b15p-1,  -0x1.28f4e4p-3, INEXACT) // BOUND 5 - 1ulp
T(RN,    0x1.4781cffffffffp-1,    0x1.c0e3bda3f6bd1p-1,  -0x1.dfaa96p-4, INEXACT) // BOUND 6 - 1ulp
T(RN,    0x1.647baffffffffp-1,     0x1.99ebe5a6febdp-1,   0x1.6bdc54p-3, INEXACT) // BOUND 7 - 1ulp
T(RN,    0x1.7bc80ffffffffp-1,    0x1.785f9b11a0b21p-1,  -0x1.4673acp-3, INEXACT) // BOUND 8 - 1ulp
T(RN,    0x1.8f5c1ffffffffp-1,    0x1.5a2dd58639a12p-1,  -0x1.c4da1cp-2, INEXACT) // BOUND 9 - 1ulp
T(RD,            0x1.7ae14p-3,    0x1.627d4e6aebaa9p+0,  -0x1.3031acp-1, INEXACT) // BOUND 1
T(RD,            0x1.32e91p-2,    0x1.4432cc777bc6dp+0,  -0x1.0423a4p-2, INEXACT) // BOUND 2
T(RD,            0x1.9ca24p-2,    0x1.27f28a9778f26p+0,  -0x1.b8882cp-1, INEXACT) // BOUND 3
T(RD,            0x1.f90b3p-2,    0x1.0e160fb695be6p+0,  -0x1.6881c2p-1, INEXACT) // BOUND 4
T(RD,            0x1.23adcp-1,    0x1.ede9ba1492b13p-1,  -0x1.db43aep-1, INEXACT) // BOUND 5
T(RD,            0x1.4781dp-1,    0x1.c0e3bda3f6bcfp-1,  -0x1.a1dc54p-1, INEXACT) // BOUND 6
T(RD,            0x1.647bbp-1,    0x1.99ebe5a6febcep-1,  -0x1.b779aep-2, INEXACT) // BOUND 7
T(RD,            0x1.7bc81p-1,    0x1.785f9b11a0b1fp-1,  -0x1.5630eep-1, INEXACT) // BOUND 8
T(RD,            0x1.8f5c2p-1,     0x1.5a2dd58639a1p-1,  -0x1.b03f34p-1, INEXACT) // BOUND 9
T(RD,    0x1.7ae1400000001p-3,    0x1.627d4e6aebaa9p+0,  -0x1.de23cap-2, INEXACT) // BOUND 1 + 1ulp
T(RD,    0x1.32e9100000001p-2,    0x1.4432cc777bc6cp+0,  -0x1.fbe6d2p-1, INEXACT) // BOUND 2 + 1ulp
T(RD,    0x1.9ca2400000001p-2,    0x1.27f28a9778f26p+0,  -0x1.2cac9ep-1, INEXACT) // BOUND 3 + 1ulp
T(RD,    0x1.f90b300000001p-2,    0x1.0e160fb695be6p+0,  -0x1.aabb2cp-2, INEXACT) // BOUND 4 + 1ulp
T(RD,    0x1.23adc00000001p-1,    0x1.ede9ba1492b12p-1,  -0x1.6c4a24p-1, INEXACT) // BOUND 5 + 1ulp
T(RD,    0x1.4781d00000001p-1,    0x1.c0e3bda3f6bcep-1,  -0x1.07c356p-1, INEXACT) // BOUND 6 + 1ulp
T(RD,    0x1.647bb00000001p-1,    0x1.99ebe5a6febcdp-1,  -0x1.270c3ap-5, INEXACT) // BOUND 7 + 1ulp
T(RD,    0x1.7bc8100000001p-1,    0x1.785f9b11a0b1ep-1,  -0x1.6b13c6p-3, INEXACT) // BOUND 8 + 1ulp
T(RD,    0x1.8f5c200000001p-1,    0x1.5a2dd58639a0fp-1,  -0x1.f84564p-3, INEXACT) // BOUND 9 + 1ulp
T(RD,    0x1.7ae13ffffffffp-3,    0x1.627d4e6aebaa9p+0,  -0x1.715174p-1, INEXACT) // BOUND 1 - 1ulp
T(RD,    0x1.32e90ffffffffp-2,    0x1.4432cc777bc6dp+0,   -0x1.083cdp-1, INEXACT) // BOUND 2 - 1ulp
T(RD,    0x1.9ca23ffffffffp-2,    0x1.27f28a9778f27p+0,  -0x1.118ee4p-3, INEXACT) // BOUND 3 - 1ulp
T(RD,    0x1.f90b2ffffffffp-2,    0x1.0e160fb695be6p+0,  -0x1.fba5eep-1, INEXACT) // BOUND 4 - 1ulp
T(RD,    0x1.23adbffffffffp-1,    0x1.ede9ba1492b15p-1,  -0x1.28f4e4p-3, INEXACT) // BOUND 5 - 1ulp
T(RD,    0x1.4781cffffffffp-1,    0x1.c0e3bda3f6bd1p-1,  -0x1.dfaa96p-4, INEXACT) // BOUND 6 - 1ulp
T(RD,    0x1.647baffffffffp-1,    0x1.99ebe5a6febcfp-1,  -0x1.a508eap-1, INEXACT) // BOUND 7 - 1ulp
T(RD,    0x1.7bc80ffffffffp-1,    0x1.785f9b11a0b21p-1,  -0x1.4673acp-3, INEXACT) // BOUND 8 - 1ulp
T(RD,    0x1.8f5c1ffffffffp-1,    0x1.5a2dd58639a12p-1,  -0x1.c4da1cp-2, INEXACT) // BOUND 9 - 1ulp
T(RZ,            0x1.7ae14p-3,    0x1.627d4e6aebaa9p+0,  -0x1.3031acp-1, INEXACT) // BOUND 1
T(RZ,            0x1.32e91p-2,    0x1.4432cc777bc6dp+0,  -0x1.0423a4p-2, INEXACT) // BOUND 2
T(RZ,            0x1.9ca24p-2,    0x1.27f28a9778f26p+0,  -0x1.b8882cp-1, INEXACT) // BOUND 3
T(RZ,            0x1.f90b3p-2,    0x1.0e160fb695be6p+0,  -0x1.6881c2p-1, INEXACT) // BOUND 4
T(RZ,            0x1.23adcp-1,    0x1.ede9ba1492b13p-1,  -0x1.db43aep-1, INEXACT) // BOUND 5
T(RZ,            0x1.4781dp-1,    0x1.c0e3bda3f6bcfp-1,  -0x1.a1dc54p-1, INEXACT) // BOUND 6
T(RZ,            0x1.647bbp-1,    0x1.99ebe5a6febcep-1,  -0x1.b779aep-2, INEXACT) // BOUND 7
T(RZ,            0x1.7bc81p-1,    0x1.785f9b11a0b1fp-1,  -0x1.5630eep-1, INEXACT) // BOUND 8
T(RZ,            0x1.8f5c2p-1,     0x1.5a2dd58639a1p-1,  -0x1.b03f34p-1, INEXACT) // BOUND 9
T(RZ,    0x1.7ae1400000001p-3,    0x1.627d4e6aebaa9p+0,  -0x1.de23cap-2, INEXACT) // BOUND 1 + 1ulp
T(RZ,    0x1.32e9100000001p-2,    0x1.4432cc777bc6cp+0,  -0x1.fbe6d2p-1, INEXACT) // BOUND 2 + 1ulp
T(RZ,    0x1.9ca2400000001p-2,    0x1.27f28a9778f26p+0,  -0x1.2cac9ep-1, INEXACT) // BOUND 3 + 1ulp
T(RZ,    0x1.f90b300000001p-2,    0x1.0e160fb695be6p+0,  -0x1.aabb2cp-2, INEXACT) // BOUND 4 + 1ulp
T(RZ,    0x1.23adc00000001p-1,    0x1.ede9ba1492b12p-1,  -0x1.6c4a24p-1, INEXACT) // BOUND 5 + 1ulp
T(RZ,    0x1.4781d00000001p-1,    0x1.c0e3bda3f6bcep-1,  -0x1.07c356p-1, INEXACT) // BOUND 6 + 1ulp
T(RZ,    0x1.647bb00000001p-1,    0x1.99ebe5a6febcdp-1,  -0x1.270c3ap-5, INEXACT) // BOUND 7 + 1ulp
T(RZ,    0x1.7bc8100000001p-1,    0x1.785f9b11a0b1ep-1,  -0x1.6b13c6p-3, INEXACT) // BOUND 8 + 1ulp
T(RZ,    0x1.8f5c200000001p-1,    0x1.5a2dd58639a0fp-1,  -0x1.f84564p-3, INEXACT) // BOUND 9 + 1ulp
T(RZ,    0x1.7ae13ffffffffp-3,    0x1.627d4e6aebaa9p+0,  -0x1.715174p-1, INEXACT) // BOUND 1 - 1ulp
T(RZ,    0x1.32e90ffffffffp-2,    0x1.4432cc777bc6dp+0,   -0x1.083cdp-1, INEXACT) // BOUND 2 - 1ulp
T(RZ,    0x1.9ca23ffffffffp-2,    0x1.27f28a9778f27p+0,  -0x1.118ee4p-3, INEXACT) // BOUND 3 - 1ulp
T(RZ,    0x1.f90b2ffffffffp-2,    0x1.0e160fb695be6p+0,  -0x1.fba5eep-1, INEXACT) // BOUND 4 - 1ulp
T(RZ,    0x1.23adbffffffffp-1,    0x1.ede9ba1492b15p-1,  -0x1.28f4e4p-3, INEXACT) // BOUND 5 - 1ulp
T(RZ,    0x1.4781cffffffffp-1,    0x1.c0e3bda3f6bd1p-1,  -0x1.dfaa96p-4, INEXACT) // BOUND 6 - 1ulp
T(RZ,    0x1.647baffffffffp-1,    0x1.99ebe5a6febcfp-1,  -0x1.a508eap-1, INEXACT) // BOUND 7 - 1ulp
T(RZ,    0x1.7bc80ffffffffp-1,    0x1.785f9b11a0b21p-1,  -0x1.4673acp-3, INEXACT) // BOUND 8 - 1ulp
T(RZ,    0x1.8f5c1ffffffffp-1,    0x1.5a2dd58639a12p-1,  -0x1.c4da1cp-2, INEXACT) // BOUND 9 - 1ulp
T(RU,            0x1.7ae14p-3,    0x1.627d4e6aebaaap+0,   0x1.9f9ca8p-2, INEXACT) // BOUND 1
T(RU,            0x1.32e91p-2,    0x1.4432cc777bc6ep+0,   0x1.7dee2ep-1, INEXACT) // BOUND 2
T(RU,            0x1.9ca24p-2,    0x1.27f28a9778f27p+0,   0x1.1ddf52p-3, INEXACT) // BOUND 3
T(RU,            0x1.f90b3p-2,    0x1.0e160fb695be7p+0,   0x1.2efc7cp-2, INEXACT) // BOUND 4
T(RU,            0x1.23adcp-1,    0x1.ede9ba1492b14p-1,   0x1.25e28ep-4, INEXACT) // BOUND 5
T(RU,            0x1.4781dp-1,     0x1.c0e3bda3f6bdp-1,   0x1.788eaep-3, INEXACT) // BOUND 6
T(RU,            0x1.647bbp-1,    0x1.99ebe5a6febcfp-1,   0x1.244328p-1, INEXACT) // BOUND 7
T(RU,            0x1.7bc81p-1,     0x1.785f9b11a0b2p-1,   0x1.539e24p-2, INEXACT) // BOUND 8
T(RU,            0x1.8f5c2p-1,    0x1.5a2dd58639a11p-1,   0x1.3f0332p-3, INEXACT) // BOUND 9
T(RU,    0x1.7ae1400000001p-3,    0x1.627d4e6aebaaap+0,   0x1.10ee1cp-1, INEXACT) // BOUND 1 + 1ulp
T(RU,    0x1.32e9100000001p-2,    0x1.4432cc777bc6dp+0,   0x1.064b66p-7, INEXACT) // BOUND 2 + 1ulp
T(RU,    0x1.9ca2400000001p-2,    0x1.27f28a9778f27p+0,   0x1.a6a6c4p-2, INEXACT) // BOUND 3 + 1ulp
T(RU,    0x1.f90b300000001p-2,    0x1.0e160fb695be7p+0,   0x1.2aa26ap-1, INEXACT) // BOUND 4 + 1ulp
T(RU,    0x1.23adc00000001p-1,    0x1.ede9ba1492b13p-1,   0x1.276bb8p-2, INEXACT) // BOUND 5 + 1ulp
T(RU,    0x1.4781d00000001p-1,    0x1.c0e3bda3f6bcfp-1,   0x1.f07954p-2, INEXACT) // BOUND 6 + 1ulp
T(RU,    0x1.647bb00000001p-1,    0x1.99ebe5a6febcep-1,   0x1.ed8f3cp-1, INEXACT) // BOUND 7 + 1ulp
T(RU,    0x1.7bc8100000001p-1,    0x1.785f9b11a0b1fp-1,   0x1.a53b0ep-1, INEXACT) // BOUND 8 + 1ulp
T(RU,    0x1.8f5c200000001p-1,     0x1.5a2dd58639a1p-1,   0x1.81eea8p-1, INEXACT) // BOUND 9 + 1ulp
T(RU,    0x1.7ae13ffffffffp-3,    0x1.627d4e6aebaaap+0,   0x1.1d5d18p-2, INEXACT) // BOUND 1 - 1ulp
T(RU,    0x1.32e90ffffffffp-2,    0x1.4432cc777bc6ep+0,   0x1.ef865ep-2, INEXACT) // BOUND 2 - 1ulp
T(RU,    0x1.9ca23ffffffffp-2,    0x1.27f28a9778f28p+0,   0x1.bb9c46p-1, INEXACT) // BOUND 3 - 1ulp
T(RU,    0x1.f90b2ffffffffp-2,    0x1.0e160fb695be7p+0,   0x1.16848cp-7, INEXACT) // BOUND 4 - 1ulp
T(RU,    0x1.23adbffffffffp-1,    0x1.ede9ba1492b16p-1,   0x1.b5c2c8p-1, INEXACT) // BOUND 5 - 1ulp
T(RU,    0x1.4781cffffffffp-1,    0x1.c0e3bda3f6bd2p-1,   0x1.c40aaep-1, INEXACT) // BOUND 6 - 1ulp
T(RU,    0x1.647baffffffffp-1,     0x1.99ebe5a6febdp-1,   0x1.6bdc54p-3, INEXACT) // BOUND 7 - 1ulp
T(RU,    0x1.7bc80ffffffffp-1,    0x1.785f9b11a0b22p-1,   0x1.ae6316p-1, INEXACT) // BOUND 8 - 1ulp
T(RU,    0x1.8f5c1ffffffffp-1,    0x1.5a2dd58639a13p-1,   0x1.1d92f2p-1, INEXACT) // BOUND 9 - 1ulp
// One in five of the very worst cases computed by Lefevre and Muller.
// Rounding these values requires evaluating the function to at least 2^(-100).
// These worst cases have been selected thanks to the filterlists 5 script
// If you want the full list please contact Jean-Michel Muller
T(RZ,    0x1.688a8428fe10ep-1,    0x1.943cc78413f14p-1,         -0x1p+0, INEXACT) // 7.041817951240163520054693435668e-01
T(RN,    0x1.297c587bf1e61p-1,    0x1.e6d01f178bb48p-1,         -0x1p-1, INEXACT) // 5.810268069553324865594845505257e-01
T(RN,    0x1.ffffef098cd9dp-1,    0x1.0796cde517c2p-10,          0x1p-1, INEXACT) // 9.999994944723088474702876737865e-01
T(RZ,    0x1.ffffed60f908dp-1,   0x1.142cb677b2f07p-10, -0x1.cba164p-34, INEXACT) // 9.999994450449932736901814678276e-01
T(RN,    0x1.ffffd94e09234p-1,   0x1.8e1d68e9f70bbp-10,         -0x1p-1, INEXACT) // 9.999988467939773251202950632432e-01
T(RN,    0x1.ffffd06342e6ap-1,   0x1.b99c4c093be27p-10,         -0x1p-1, INEXACT) // 9.999985810440652489461399454740e-01
T(RZ,    0x1.fffffca706e81p-1,   0x1.d462b88fa7b59p-12,         -0x1p+0, INEXACT) // 9.999999002352099042312261190091e-01
T(RZ,    0x1.fffffc025060dp-1,   0x1.ff6bd2afd78a3p-12,         -0x1p+0, INEXACT) // 9.999998810600928544900511951710e-01
T(RN,     0x1.ffffffb0d509p-1,   0x1.1cb963f486a47p-13,         -0x1p-1, INEXACT) // 9.999999907836514267955863033421e-01
T(RN,    0x1.ffffff07fbfafp-1,   0x1.f7f3d4503efbcp-13,         -0x1p-1, INEXACT) // 9.999999711271722047101206953812e-01
T(RN,    0x1.ffffffd7110e7p-1,   0x1.997783346a6e5p-14,   0x1.fffffcp-2, INEXACT) // 9.999999952347281562126113385602e-01
T(RN,    0x1.fffffffa9b9aep-1,   0x1.293ab61a8a8f9p-15,  -0x1.ffffecp-2, INEXACT) // 9.999999993722690216912951655104e-01
T(RZ,    0x1.fffffff7490e9p-1,   0x1.79dce5fdc9126p-15, -0x1.bfd6dep-24, INEXACT) // 9.999999989854845283687723167532e-01
T(RN,    0x1.fffffff092e7bp-1,   0x1.f6bc0ec199fedp-15,    0x1.fffffp-2, INEXACT) // 9.999999982041595236736952756473e-01
T(RZ,    0x1.fffffff5a1b3dp-1,   0x1.9c28b4abe4b2bp-15,  -0x1.fffffep-1, INEXACT) // 9.999999987929651945606224217045e-01
T(RN,    0x1.fffffff482ea5p-1,   0x1.b1daa974f9a83p-15,  -0x1.fffffap-2, INEXACT) // 9.999999986625495163039545332140e-01
T(RZ,    0x1.fffffffcef9b2p-1,   0x1.c01cd15c171eep-16,  -0x1.ffffeep-1, INEXACT) // 9.999999996432988869088376304717e-01
T(RN,    0x1.fffffffdfcb84p-1,   0x1.6b32528d0ad4cp-16,   0x1.ffffa8p-2, INEXACT) // 9.999999997656776606902440107660e-01
T(RZ,    0x1.fffffffde9656p-1,    0x1.71f1af76d131p-16, -0x1.605da8p-25, INEXACT) // 9.999999997568902454503358967486e-01
T(RN,    0x1.ffffffff94636p-1,   0x1.4bf4a030d7adfp-17,  -0x1.fffffep-2, INEXACT) // 9.999999999510638115651772750425e-01
T(RN,    0x1.ffffffff92d95p-1,   0x1.4e5242845c86cp-17,   0x1.ffff6ep-2, INEXACT) // 9.999999999503638159481511138438e-01
T(RZ,    0x1.ffffffff0ecdep-1,   0x1.f0f9b0a2e462dp-17,   -0x1.fffffp-1, INEXACT) // 9.999999998903168485497872097767e-01
T(RZ,    0x1.ffffffffefd6ap-1,   0x1.014a2b16721ecp-18, -0x1.697ebep-18, INEXACT) // 9.999999999926505456215863887337e-01
T(RN,    0x1.ffffffffecec6p-1,   0x1.178820dae0668p-18,   0x1.fffc7ap-2, INEXACT) // 9.999999999913249393301839518244e-01
T(RZ,    0x1.ffffffffe5b99p-1,   0x1.480f37d7945a1p-18,  -0x1.01952p-16, INEXACT) // 9.999999999880514467420766777650e-01
T(RZ,    0x1.ffffffffc88afp-1,   0x1.dc9b0f9e2836ep-18, -0x1.64974ep-17, INEXACT) // 9.999999999747809509287321816373e-01
T(RN,    0x1.ffffffffc859ep-1,   0x1.dd6db40e49582p-18,  -0x1.fffe0cp-2, INEXACT) // 9.999999999746937984212991068489e-01
T(RN,    0x1.ffffffffda901p-1,   0x1.879720fe10cdcp-18,   0x1.fffc8ep-2, INEXACT) // 9.999999999829755070734904620622e-01
T(RZ,    0x1.ffffffffd4222p-1,   0x1.a7e2693b54bb1p-18,  -0x1.fffe9ap-1, INEXACT) // 9.999999999800517347381401123130e-01
T(RN,    0x1.ffffffffd3309p-1,   0x1.ac6b4fdaf8f8ep-18,  -0x1.fffdd6p-2, INEXACT) // 9.999999999796226335391224893101e-01
T(RZ,    0x1.fffffffffae4ap-1,   0x1.2142d943e09f1p-19, -0x1.770038p-14, INEXACT) // 9.999999999976776354770890975487e-01
T(RN,    0x1.fffffffff9fbdp-1,   0x1.39f637497cf72p-19,   0x1.ffed56p-2, INEXACT) // 9.999999999972640774004162267374e-01
T(RZ,    0x1.fffffffff09dbp-1,   0x1.f60c3d0bca448p-19,  -0x1.c62c9p-15, INEXACT) // 9.999999999930041516549295010918e-01
T(RZ,    0x1.eb240b349ff64p-1,     0x1.254d3598c30ap-2,         -0x1p+0, INEXACT) // 9.592593671550102563116979581537e-01
T(RN,    0x1.e63a50440b91bp-1,    0x1.46487ab808fa9p-2,          0x1p-1, INEXACT) // 9.496636469901064137033586121106e-01
T(RN,    0x1.dce3b4d53f901p-1,    0x1.7d6d7e84c63b4p-2,         -0x1p-1, INEXACT) // 9.314247618019920738063888165925e-01
T(RN,    0x1.fffffffffc43ep-1,   0x1.eebd86a7e0818p-20,  -0x1.fff364p-2, INEXACT) // 9.999999999983015808169284355245e-01
T(RN,    0x1.fffffffffd93dp-1,   0x1.8e74ff86e4b93p-20,  -0x1.ffd8eep-2, INEXACT) // 9.999999999988983256926644571649e-01
T(RN,     0x1.fffffffffd2dp-1,   0x1.ae37f2d5a8a2ep-20,   0x1.ffe816p-2, INEXACT) // 9.999999999987156940051136189140e-01
T(RZ,    0x1.ffffffffffaa8p-1,   0x1.27e451bb94505p-21,  -0x1.02483p-11, INEXACT) // 9.999999999998481214902312785853e-01
T(RZ,    0x1.ffffffffff22ep-1,   0x1.dbd9456a821e5p-21, -0x1.421d7ap-11, INEXACT) // 9.999999999996072030938876196160e-01
T(RZ,    0x1.ffffffffff58fp-1,   0x1.9d9bc758f2bc1p-21,  -0x1.ff891ep-1, INEXACT) // 9.999999999997032373855176956567e-01
T(RZ,     0x1.fffffffffff3p-1,   0x1.cd82b44615a03p-23,  -0x1.81f258p-9, INEXACT) // 9.999999999999769073610877967440e-01
T(RN,    0x1.fffffffffff2bp-1,   0x1.d3064dcc8ae77p-23,  -0x1.f7e0b2p-2, INEXACT) // 9.999999999999763522495754841657e-01
T(RZ,    0x1.fffffffffff17p-1,   0x1.e87573f6c42d7p-23,  -0x1.fa3ac8p-1, INEXACT) // 9.999999999999741318035262338526e-01
T(RN,    0x1.fffffffffff0dp-1,   0x1.f2d4a45635653p-23,  -0x1.f34688p-2, INEXACT) // 9.999999999999730215805016086961e-01
T(RZ,    0x1.fffffffffffdfp-1,   0x1.6fa6ea162d0f2p-24,    -0x1.84a5p-6, INEXACT) // 9.999999999999963362640187369834e-01
T(RZ,    0x1.fffffffffffdap-1,   0x1.8a85c24f7065bp-24,  -0x1.dcc278p-1, INEXACT) // 9.999999999999957811525064244051e-01
T(RZ,    0x1.ffffffffffff8p-1,   0x1.6a09e667f3bcdp-25,  -0x1.2724e6p-5, INEXACT) // 9.999999999999991118215802998748e-01
T(RN,    0x1.ffffffffffff3p-1,   0x1.cd82b446159f4p-25,  -0x1.6bec02p-2, INEXACT) // 9.999999999999985567100679872965e-01
T(RN,    0x1.faad6d27476d2p-1,    0x1.278f94a153d2bp-3,          0x1p-1, INEXACT) // 9.896043882797249668925587684498e-01
T(RN,    0x1.f335b29c05035p-1,    0x1.cabb034220afcp-3,         -0x1p-1, INEXACT) // 9.750190558866110857039188886120e-01
T(RZ,    0x1.f23be534ba3e8p-1,    0x1.dbfbe258b6554p-3, -0x1.a85cbap-47, INEXACT) // 9.731132151474612967945176933426e-01
T(RZ,    0x1.f10fc61e2c78fp-1,    0x1.efeef61d39ac1p-3,         -0x1p+0, INEXACT) // 9.708234702904848800741888226185e-01
T(RN,    0x1.feeca7ab99a61p-1,    0x1.098afa65a1a05p-4,         -0x1p-1, INEXACT) // 9.978992840741051084663126857777e-01
T(RN,    0x1.fece3319e4315p-1,     0x1.17d94bdaccedp-4,          0x1p-1, INEXACT) // 9.976669282060323107330646053015e-01
T(RN,    0x1.fd2fc398ee733p-1,    0x1.ad979e726361bp-4,         -0x1p-1, INEXACT) // 9.945050357993977518944461735373e-01
T(RZ,    0x1.ff08f4f87ec0ap-1,    0x1.f70ad89ccacf9p-5, -0x1.89a6bap-44, INEXACT) // 9.981152108515527476839679366094e-01
T(RN,    0x1.ffcebb5298934p-1,    0x1.c13d20b108a93p-6,         -0x1p-1, INEXACT) // 9.996241129231635547114365181187e-01
T(RN,    0x1.fffa056e1de78p-1,    0x1.38fb2e3e655b4p-7,          0x1p-1, INEXACT) // 9.999543854637087392234207072761e-01
T(RN,     0x1.fff8602cd2dcp-1,    0x1.616ffa520e2c5p-7,          0x1p-1, INEXACT) // 9.999418310848611213259573560208e-01
T(RN,    0x1.fff630dcb5242p-1,    0x1.90e47d6d22876p-7,         -0x1p-1, INEXACT) // 9.999251622599063527019325192668e-01
T(RN,    0x1.fff42bd16a254p-1,     0x1.b83c1317beafp-7,         -0x1p-1, INEXACT) // 9.999097531445593212140465766424e-01
T(RN,     0x1.fff2475257bap-1,    0x1.da259efa0b49bp-7,          0x1p-1, INEXACT) // 9.998953140274018380750931100920e-01
T(RN,    0x1.fffe5fb9e8e35p-1,    0x1.4671e8c50077ep-8,          0x1p-1, INEXACT) // 9.999875940743040425573440188600e-01
T(RN,    0x1.fffe3e569b6f5p-1,    0x1.5348b5e4a64fbp-8,          0x1p-1, INEXACT) // 9.999865990373267843338567217870e-01
T(RZ,    0x1.fffd61b7cafeep-1,    0x1.9e3cd27d785ecp-8,         -0x1p+0, INEXACT) // 9.999800240379934646028914357885e-01
T(RN,    0x1.ffffbd341ca3bp-1,    0x1.05887ad8a4ea7p-9,          0x1p-1, INEXACT) // 9.999980093110204526496431753912e-01
T(RZ,    0x1.ffff9952d2175p-1,    0x1.444111b54c1fcp-9,         -0x1p+0, INEXACT) // 9.999969400023888121964432684763e-01
T(RZ,    0x1.ffff07c013eecp-1,     0x1.f830c0d1fb4ep-9,         -0x1p+0, INEXACT) // 9.999926015825315595009215030586e-01
T(RZ,    0x1.9d464ed5224b4p-4,    0x1.78400af71dc24p+0,  -0x1.be5d4p-55, INEXACT) // 1.008971290012990462692243909260e-01
T(RN,   0x1.313faeb270984p-10,    0x1.91d3655774e16p+0,          0x1p-1, INEXACT) // 1.164431607876354780872762972876e-03
T(RZ,   0x1.5d34b171ec691p-10,    0x1.91c868163526fp+0,         -0x1p+0, INEXACT) // 1.332114534744386702760921004085e-03
T(RN,   0x1.784165bb07615p-10,    0x1.91c1a4e8b6369p+0,          0x1p-1, INEXACT) // 1.435300668851784535243187868048e-03
T(RN,   0x1.7239b57b9e41fp-11,    0x1.91f16e0d52d6fp+0,         -0x1p-1, INEXACT) // 7.061489590817238452477577759225e-04
T(RN,   0x1.7541208b069cdp-11,    0x1.91f10d1fef512p+0,         -0x1p-1, INEXACT) // 7.119262749058441691954457475333e-04
T(RN,   0x1.9787d818010a1p-11,    0x1.91ecc448e9c11p+0,         -0x1p-1, INEXACT) // 7.773030110915965214604672617327e-04
T(RN,   0x1.aa4a6197dbabbp-11,    0x1.91ea6bf7ad54fp+0,          0x1p-1, INEXACT) // 8.130847008781175297084664599367e-04
T(RZ,   0x1.95d8fed4497f2p-11,    0x1.91ecfa241347ep+0, -0x1.1c589ap-52, INEXACT) // 7.740929382051826932592542007683e-04
T(RZ,   0x1.8e78bab627239p-11,    0x1.91ede62c9b993p+0, -0x1.242608p-51, INEXACT) // 7.600242595518564474657563501125e-04
T(RZ,   0x1.43efedd9d8c4cp-12,    0x1.920b76455fccdp+0,  -0x1.1a13ep-51, INEXACT) // 3.089306097676144512859108814951e-04
T(RN,   0x1.3fb7dc443bc04p-12,     0x1.920bb9c6795cp+0,          0x1p-1, INEXACT) // 3.049070403581823855004850898354e-04
T(RN,   0x1.8602b333e9fbap-13,    0x1.9213852ea8048p+0,          0x1p-1, INEXACT) // 1.859715208614146531203303869262e-04
T(RN,   0x1.8359520a26523p-13,    0x1.92139a79b158cp+0,          0x1p-1, INEXACT) // 1.847023525598868781607414524260e-04
T(RN,   0x1.7ef5b6b8d9c69p-14,    0x1.9219b96d67ca7p+0,          0x1p-1, INEXACT) // 9.130473598660680172121179021261e-05
T(RN,   0x1.989dafae502e8p-15,    0x1.921c8408e36f8p+0,          0x1p-1, INEXACT) // 4.871081852054153340028652685589e-05
T(RN,   0x1.a9bf18df252f1p-15,    0x1.921c61c6110d1p+0,         -0x1p-1, INEXACT) // 5.075293460624585411807355161962e-05
T(RN,   0x1.635e74f2d5adap-15,    0x1.921cee8758e85p+0,          0x1p-1, INEXACT) // 4.236328267974926516537675924567e-05
T(RZ,   0x1.debd95835e09dp-15,    0x1.921bf7c917c21p+0,  -0x1.645a3p-54, INEXACT) // 5.707032235141680037932357394403e-05
T(RN,   0x1.277e36864acbdp-16,     0x1.921e8dc60c4bp+0,          0x1p-1, INEXACT) // 1.761275645965615564117641433928e-05
T(RN,   0x1.28ac3b5a8a01dp-16,    0x1.921e8c980776cp+0,          0x1p-1, INEXACT) // 1.768307570607095924428327216038e-05
T(RN,   0x1.be56bfb36a47ap-16,    0x1.921df6ed831d4p+0,          0x1p-1, INEXACT) // 2.660386935607716697932759175593e-05
T(RN,   0x1.b848f4a3035b6p-16,    0x1.921dfcfb4e2dap+0,         -0x1p-1, INEXACT) // 2.624303000336110266435193927315e-05
T(RZ,    0x1.ef8434b14effp-16,    0x1.921dc5c00e1efp+0,         -0x1p+0, INEXACT) // 2.953508073243177453268137888642e-05
T(RN,   0x1.0b62b5cd6cabap-17,    0x1.921f2f92e7eadp+0,          0x1p-1, INEXACT) // 7.968711453231403022941584102234e-06
T(RZ,   0x1.ad4065459689fp-17,    0x1.921edea4102eap+0, -0x1.cd275ap-52, INEXACT) // 1.279269293801384723113356151059e-05
T(RZ,   0x1.c83a26b10c734p-17,    0x1.921ed1272f78dp+0,         -0x1p+0, INEXACT) // 1.359662869235590956307549448390e-05
T(RZ,   0x1.3ec3f8c14c803p-18,    0x1.921f659344a12p+0,         -0x1p+0, INEXACT) // 4.749976313877040988507393509677e-06
T(RZ,   0x1.9b6948e04694bp-18,    0x1.921f4e69f0996p+0,         -0x1p+0, INEXACT) // 6.130505625168775100063394550842e-06
T(RN,   0x1.c8a488732283ap-18,    0x1.921f431b20b4bp+0,         -0x1p-1, INEXACT) // 6.804506585864463497612987519236e-06
T(RZ,   0x1.01c5b7c0229e1p-19,    0x1.921f950b8bd98p+0,  -0x1.e7047p-51, INEXACT) // 1.920553558025883386027295521292e-06
T(RN,   0x1.068d8ef862943p-19,    0x1.921f947290f28p+0,          0x1p-1, INEXACT) // 1.956172010324529991455921526522e-06
T(RZ,   0x1.2b69aa1f223b4p-19,    0x1.921f8fd70d8d9p+0,         -0x1p+0, INEXACT) // 2.230798841266741920131601306654e-06
T(RZ,   0x1.23dab68946596p-20,    0x1.921fa3069768fp+0, -0x1.4288a8p-52, INEXACT) // 1.087242170355562643607174808102e-06
T(RZ,   0x1.17b8424e4660fp-20,    0x1.921fa3c8beacap+0, -0x1.a3bd08p-53, INEXACT) // 1.042037314719061280335831408406e-06
T(RN,   0x1.272eae19c6573p-20,    0x1.921fa2d157effp+0,          0x1p-1, INEXACT) // 1.099639922624799454203034336508e-06
T(RN,   0x1.4723101ec63f9p-20,    0x1.921fa0d211cf9p+0,         -0x1p-1, INEXACT) // 1.218680160958031641178452887664e-06
T(RZ,   0x1.32ab73bc464f4p-20,    0x1.921fa2198b95cp+0, -0x1.379bc4p-52, INEXACT) // 1.142433787631934984714999342659e-06
T(RN,   0x1.fd4e1b87c548ap-20,     0x1.921f956f6119p+0,         -0x1p-1, INEXACT) // 1.897309376224374104403938914865e-06
T(RZ,   0x1.04a1d9808d25fp-21,    0x1.921fad1f34058p+0,  -0x1.a5b43p-51, INEXACT) // 4.854653497589467437201070192099e-07
T(RZ,   0x1.3dab16528d1cdp-21,    0x1.921fab56ea1eep+0,         -0x1p+0, INEXACT) // 5.917033355008728283519329506357e-07
T(RZ,   0x1.2559dfa91a5e6p-22,    0x1.921fb0aedb52dp+0,         -0x1p+0, INEXACT) // 2.732044728838702056915462533515e-07
T(RZ,   0x1.9ab830451a576p-22,    0x1.921faed962106p+0,         -0x1p+0, INEXACT) // 3.825123296498586920430149370398e-07
T(RN,   0x1.d7deb2d31a51bp-22,    0x1.921fade4c8064p+0,          0x1p-1, INEXACT) // 4.394631051897640001875102160750e-07
T(RZ,   0x1.dff8a6351a50dp-22,    0x1.921fadc46038bp+0, -0x1.addbaep-52, INEXACT) // 4.470080939346529947326432542082e-07
T(RN,   0x1.6ee3da5634c2dp-23,    0x1.921fb2667b1cdp+0,         -0x1p-1, INEXACT) // 1.708464931251012953418233009453e-07
T(RZ,   0x1.924f4b1a34c23p-23,    0x1.921fb21fa43b4p+0,         -0x1p+0, INEXACT) // 1.873400712950081832858538260708e-07
T(RZ,   0x1.cd4571d234c0ep-23,    0x1.921fb1a9b7edep+0, -0x1.e00356p-51, INEXACT) // 2.147961724653942871804521066309e-07
T(RN,   0x1.e1fe7f0c69887p-24,    0x1.921fb36244527p+0,         -0x1p-1, INEXACT) // 1.122230026186532298037123295785e-07
T(RN,    0x1.567b0af8d313p-25,     0x1.921fb499054cp+0,         -0x1p-1, INEXACT) // 3.986999347910600196420857418977e-08
T(RN,   0x1.e73bf758d312dp-25,    0x1.921fb450a4d5dp+0,         -0x1p-1, INEXACT) // 5.672153119990270973816730488461e-08
T(RN,    0x1.1f495f9db9bb9p-5,    0x1.8924f19ccc408p+0,          0x1p-1, INEXACT) // 3.506916689894219035794620253910e-02
T(RN,    0x1.552609c6f3437p-5,    0x1.8775badc293a3p+0,         -0x1p-1, INEXACT) // 4.164411458587163189504209981351e-02
T(RN,    0x1.59d20f7f204a5p-5,    0x1.8750524261966p+0,         -0x1p-1, INEXACT) // 4.221442248036425676227523240414e-02
T(RZ,    0x1.8b20deeb74cabp-5,    0x1.85c574332d575p+0,         -0x1p+0, INEXACT) // 4.823344744695508973242326078434e-02
T(RZ,    0x1.3c7536f0ecbdcp-6,    0x1.8d2dcc41734d8p+0,         -0x1p+0, INEXACT) // 1.931505551665312070408475619843e-02
T(RZ,    0x1.4e95279f75385p-6,    0x1.8ce548d46da0ep+0,         -0x1p+0, INEXACT) // 2.042130345747096911712681333029e-02
T(RZ,    0x1.8649b0d970141p-6,    0x1.8c0668b2366fcp+0, -0x1.c57928p-51, INEXACT) // 2.382128019758167694619466203676e-02
T(RN,    0x1.bb271ef23e5a8p-6,    0x1.8b32e16f0c084p+0,         -0x1p-1, INEXACT) // 2.704790136428916746957895611558e-02
T(RZ,    0x1.0cb49c5fcf88dp-7,    0x1.90064a80c7f5bp+0,         -0x1p+0, INEXACT) // 8.200241427058574741892904569340e-03
T(RZ,    0x1.83049752ddf78p-7,     0x1.8f19a77a2a05p+0, -0x1.d1d774p-53, INEXACT) // 1.181085003712188663538285027244e-02
T(RN,    0x1.d652a9b8f530cp-7,    0x1.8e7307abfa96ap+0,         -0x1p-1, INEXACT) // 1.435311591368695210979566923015e-02
T(RZ,    0x1.0e2d4b52f447ep-8,    0x1.911187c6c81abp+0,         -0x1p+0, INEXACT) // 4.122572793634591767353292368625e-03
T(RZ,    0x1.1eab8aaafed95p-8,    0x1.9101097dae24dp+0, -0x1.8d993ap-52, INEXACT) // 4.374238352279920423459902423247e-03
T(RN,    0x1.6eded9a52b89bp-8,    0x1.90b0d5ed09b23p+0,         -0x1p-1, INEXACT) // 5.597999702486112887089841905208e-03
T(RN,    0x1.7560e989e0472p-8,    0x1.90aa53d657971p+0,          0x1p-1, INEXACT) // 5.697304741148477916223846762023e-03
T(RN,    0x1.884d68a0873e1p-8,    0x1.9097674216808p+0,          0x1p-1, INEXACT) // 5.986059230534275001078814426592e-03
T(RN,    0x1.61191e4ad34afp-9,    0x1.916f28a71ebd2p+0,         -0x1p-1, INEXACT) // 2.693924854077232432930655292580e-03
T(RZ,    0x1.bc52bd8cab8c1p-9,    0x1.91418bc999cd2p+0,         -0x1p+0, INEXACT) // 3.389917028775974328774767130312e-03
T(RZ,    0x1.d6cef073cc8c7p-9,    0x1.91344daadc0fdp+0,         -0x1p+0, INEXACT) // 3.591982700435900326824123496294e-03
