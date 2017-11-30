// expm1.testdata
// copyright (C) 2005 Ch. Q. Lauter and V.Lefevre
// This file is part of crlibm and is distributed under the GNU Public Licence
// See file COPYING for details
// The following lines are either comments (beginning with a #)
// or give
//   1/ a rounding mode : RN|RU|RD|RZ (crlibm syntax) or  N|P|M|Z (libmcr syntax)
//   2/ The high and low hexadecimal halves of an input
//   3/ The high and low hexadecimal halves of the expected corresponding output
// TODO: VERIFY THIS VALUES
// Special cases
T(RN,                  0x0p+0,                  0x0p+0,          0x0p+0, 0) // zero
T(RN,                 -0x0p+0,                 -0x0p+0,          0x0p+0, 0) // -zero
T(RU,                  0x0p+0,                  0x0p+0,          0x0p+0, 0) // zero
T(RU,                 -0x0p+0,                 -0x0p+0,          0x0p+0, 0) // -zero
T(RD,                  0x0p+0,                  0x0p+0,          0x0p+0, 0) // zero
T(RD,                 -0x0p+0,                 -0x0p+0,          0x0p+0, 0) // -zero
T(RZ,                  0x0p+0,                  0x0p+0,          0x0p+0, 0) // zero
T(RZ,                 -0x0p+0,                 -0x0p+0,          0x0p+0, 0) // -zero
T(RN,               0x1p-1074,               0x1p-1074,          0x0p+0, INEXACT|UNDERFLOW) // smallest denorm positive
T(RN,              -0x1p-1074,              -0x1p-1074,          0x0p+0, INEXACT|UNDERFLOW) // smallest denorm negative
T(RU,               0x1p-1074,               0x1p-1073,          0x1p+0, INEXACT|UNDERFLOW) // smallest denorm positive
T(RU,              -0x1p-1074,                 -0x0p+0,          0x1p+0, INEXACT|UNDERFLOW) // smallest denorm negative
T(RD,               0x1p-1074,               0x1p-1074,          0x0p+0, INEXACT|UNDERFLOW) // smallest denorm positive
T(RD,              -0x1p-1074,              -0x1p-1074,          0x0p+0, INEXACT|UNDERFLOW) // smallest denorm negative
T(RZ,               0x1p-1074,               0x1p-1074,          0x0p+0, INEXACT|UNDERFLOW) // smallest denorm positive
T(RZ,              -0x1p-1074,                 -0x0p+0,          0x1p+0, INEXACT|UNDERFLOW) // smallest denorm negative
T(RN,                     inf,                     inf,          0x0p+0, 0) // +inf
T(RN,                    -inf,                 -0x1p+0,          0x0p+0, 0) // -inf
T(RU,                     inf,                     inf,          0x0p+0, 0) // +inf
T(RU,                    -inf,                 -0x1p+0,          0x0p+0, 0) // -inf
T(RD,                     inf,                     inf,          0x0p+0, 0) // +inf
T(RD,                    -inf,                 -0x1p+0,          0x0p+0, 0) // -inf
T(RZ,                     inf,                     inf,          0x0p+0, 0) // +inf
T(RZ,                    -inf,                 -0x1p+0,          0x0p+0, 0) // -inf
T(RN,                     nan,                     nan,          0x0p+0, 0) // NaN
T(RU,                     nan,                     nan,          0x0p+0, 0) // NaN
T(RD,                     nan,                     nan,          0x0p+0, 0) // NaN
T(RZ,                     nan,                     nan,          0x0p+0, 0) // NaN
// Overflows
T(RN,    0x1.62e42fefa39eep+9, 0x1.ffffffffffb2ap+1023,  -0x1.b0e264p-4, INEXACT)
T(RN,    0x1.62e42fefa39efp+9, 0x1.fffffffffff2ap+1023,  -0x1.b0e264p-4, INEXACT)
T(RN,     0x1.62e42fefa39fp+9,                     inf,          0x0p+0, INEXACT|OVERFLOW)
T(RN,    0x1.62e42fefa39f1p+9,                     inf,          0x0p+0, INEXACT|OVERFLOW)
T(RU,    0x1.62e42fefa39eep+9, 0x1.ffffffffffb2bp+1023,   0x1.c9e3b4p-1, INEXACT)
T(RU,    0x1.62e42fefa39efp+9, 0x1.fffffffffff2bp+1023,   0x1.c9e3b4p-1, INEXACT)
T(RU,     0x1.62e42fefa39fp+9,                     inf,          0x0p+0, INEXACT|OVERFLOW)
T(RU,    0x1.62e42fefa39f1p+9,                     inf,          0x0p+0, INEXACT|OVERFLOW)
T(RD,    0x1.62e42fefa39eep+9, 0x1.ffffffffffb2ap+1023,  -0x1.b0e264p-4, INEXACT)
T(RD,    0x1.62e42fefa39efp+9, 0x1.fffffffffff2ap+1023,  -0x1.b0e264p-4, INEXACT)
T(RD,     0x1.62e42fefa39fp+9, 0x1.fffffffffffffp+1023,         -0x1p+0, INEXACT|OVERFLOW)
T(RD,    0x1.62e42fefa39f1p+9, 0x1.fffffffffffffp+1023,         -0x1p+0, INEXACT|OVERFLOW)
T(RZ,    0x1.62e42fefa39eep+9, 0x1.ffffffffffb2ap+1023,  -0x1.b0e264p-4, INEXACT)
T(RZ,    0x1.62e42fefa39efp+9, 0x1.fffffffffff2ap+1023,  -0x1.b0e264p-4, INEXACT)
T(RZ,     0x1.62e42fefa39fp+9, 0x1.fffffffffffffp+1023,         -0x1p+0, INEXACT|OVERFLOW)
T(RZ,    0x1.62e42fefa39f1p+9, 0x1.fffffffffffffp+1023,         -0x1p+0, INEXACT|OVERFLOW)
// -1.0 + correction in result
T(RN,   -0x1.205966f2b4f12p+5,   -0x1.ffffffffffffep-1, -0x1.6dca04p-48, INEXACT)
T(RN,   -0x1.2b708872320e1p+5,   -0x1.fffffffffffffp-1,          0x1p-1, INEXACT)
T(RN,   -0x1.2b708872320e2p+5,                 -0x1p+0,         -0x1p-2, INEXACT)
T(RN,   -0x1.2b708872320e3p+5,                 -0x1p+0,         -0x1p-2, INEXACT)
T(RN,                -0x1p+81,                 -0x1p+0,          0x0p+0, INEXACT)
T(RU,   -0x1.205966f2b4f12p+5,   -0x1.ffffffffffffdp-1,          0x1p+0, INEXACT)
T(RU,              -0x1.25p+5,   -0x1.ffffffffffffep-1,   0x1.c36f84p-1, INEXACT)
T(RU,   -0x1.2b708872320e1p+5,   -0x1.fffffffffffffp-1,          0x1p-1, INEXACT)
T(RU,   -0x1.2b708872320e2p+5,   -0x1.fffffffffffffp-1,          0x1p-1, INEXACT)
T(RU,   -0x1.2b708872320e3p+5,   -0x1.fffffffffffffp-1,          0x1p-1, INEXACT)
T(RU,                -0x1p+81,   -0x1.fffffffffffffp-1,          0x1p+0, INEXACT)
T(RD,   -0x1.205966f2b4f12p+5,   -0x1.ffffffffffffep-1, -0x1.6dca04p-48, INEXACT)
T(RD,              -0x1.25p+5,   -0x1.fffffffffffffp-1,  -0x1.e483dep-4, INEXACT)
T(RD,   -0x1.2b708872320e1p+5,                 -0x1p+0,         -0x1p-2, INEXACT)
T(RD,   -0x1.2b708872320e2p+5,                 -0x1p+0,         -0x1p-2, INEXACT)
T(RD,   -0x1.2b708872320e3p+5,                 -0x1p+0,         -0x1p-2, INEXACT)
T(RD,                -0x1p+81,                 -0x1p+0,          0x0p+0, INEXACT)
T(RZ,   -0x1.205966f2b4f12p+5,   -0x1.ffffffffffffdp-1,          0x1p+0, INEXACT)
T(RZ,              -0x1.25p+5,   -0x1.ffffffffffffep-1,   0x1.c36f84p-1, INEXACT)
T(RZ,   -0x1.2b708872320e1p+5,   -0x1.fffffffffffffp-1,          0x1p-1, INEXACT)
T(RZ,   -0x1.2b708872320e2p+5,   -0x1.fffffffffffffp-1,          0x1p-1, INEXACT)
T(RZ,   -0x1.2b708872320e3p+5,   -0x1.fffffffffffffp-1,          0x1p-1, INEXACT)
T(RZ,                -0x1p+81,   -0x1.fffffffffffffp-1,          0x1p+0, INEXACT)
// Passing into "x + correction is result" path
T(RN,   0x1.ffffffffffffep-55,   0x1.ffffffffffffep-55,         -0x1p-2, INEXACT)
T(RN,   0x1.fffffffffffffp-55,   0x1.fffffffffffffp-55,         -0x1p-2, INEXACT)
T(RN,                 0x1p-54,                 0x1p-54,         -0x1p-3, INEXACT)
T(RN,   0x1.0000000000001p-54,   0x1.0000000000001p-54,         -0x1p-3, INEXACT)
T(RN,   0x1.0000000000002p-54,   0x1.0000000000002p-54,         -0x1p-3, INEXACT)
T(RU,   0x1.ffffffffffffdp-55,   0x1.ffffffffffffep-55,        0x1.8p-1, INEXACT)
T(RU,   0x1.ffffffffffffep-55,   0x1.fffffffffffffp-55,        0x1.8p-1, INEXACT)
T(RU,   0x1.fffffffffffffp-55,                 0x1p-54,        0x1.8p-2, INEXACT)
T(RU,                 0x1p-54,   0x1.0000000000001p-54,        0x1.cp-1, INEXACT)
T(RU,   0x1.0000000000001p-54,   0x1.0000000000002p-54,        0x1.cp-1, INEXACT)
T(RU,   0x1.0000000000002p-54,   0x1.0000000000003p-54,        0x1.cp-1, INEXACT)
T(RD,   0x1.ffffffffffffep-55,   0x1.ffffffffffffep-55,         -0x1p-2, INEXACT)
T(RD,   0x1.fffffffffffffp-55,   0x1.fffffffffffffp-55,         -0x1p-2, INEXACT)
T(RD,                 0x1p-54,                 0x1p-54,         -0x1p-3, INEXACT)
T(RD,   0x1.0000000000001p-54,   0x1.0000000000001p-54,         -0x1p-3, INEXACT)
T(RD,   0x1.0000000000002p-54,   0x1.0000000000002p-54,         -0x1p-3, INEXACT)
T(RZ,   0x1.ffffffffffffep-55,   0x1.ffffffffffffep-55,         -0x1p-2, INEXACT)
T(RZ,   0x1.fffffffffffffp-55,   0x1.fffffffffffffp-55,         -0x1p-2, INEXACT)
T(RZ,                 0x1p-54,                 0x1p-54,         -0x1p-3, INEXACT)
T(RZ,   0x1.0000000000001p-54,   0x1.0000000000001p-54,         -0x1p-3, INEXACT)
T(RZ,   0x1.0000000000002p-54,   0x1.0000000000002p-54,         -0x1p-3, INEXACT)
T(RN,  -0x1.ffffffffffffep-55,  -0x1.ffffffffffffep-55,         -0x1p-2, INEXACT)
T(RN,  -0x1.fffffffffffffp-55,  -0x1.fffffffffffffp-55,         -0x1p-2, INEXACT)
T(RN,                -0x1p-54,                -0x1p-54,         -0x1p-3, INEXACT)
T(RN,  -0x1.0000000000001p-54,  -0x1.0000000000001p-54,         -0x1p-3, INEXACT)
T(RN,  -0x1.0000000000002p-54,  -0x1.0000000000002p-54,         -0x1p-3, INEXACT)
T(RU,  -0x1.ffffffffffffdp-55,  -0x1.ffffffffffffcp-55,        0x1.8p-1, INEXACT)
T(RU,  -0x1.ffffffffffffep-55,  -0x1.ffffffffffffdp-55,        0x1.8p-1, INEXACT)
T(RU,  -0x1.fffffffffffffp-55,  -0x1.ffffffffffffep-55,        0x1.8p-1, INEXACT)
T(RU,                -0x1p-54,  -0x1.fffffffffffffp-55,        0x1.8p-1, INEXACT)
T(RU,  -0x1.0000000000001p-54,                -0x1p-54,        0x1.cp-1, INEXACT)
T(RU,  -0x1.0000000000002p-54,  -0x1.0000000000001p-54,        0x1.cp-1, INEXACT)
T(RD,  -0x1.ffffffffffffep-55,  -0x1.ffffffffffffep-55,         -0x1p-2, INEXACT)
T(RD,  -0x1.fffffffffffffp-55,  -0x1.fffffffffffffp-55,         -0x1p-2, INEXACT)
T(RD,                -0x1p-54,                -0x1p-54,         -0x1p-3, INEXACT)
T(RD,  -0x1.0000000000001p-54,  -0x1.0000000000001p-54,         -0x1p-3, INEXACT)
T(RD,  -0x1.0000000000002p-54,  -0x1.0000000000002p-54,         -0x1p-3, INEXACT)
T(RZ,  -0x1.ffffffffffffep-55,  -0x1.ffffffffffffdp-55,        0x1.8p-1, INEXACT)
T(RZ,  -0x1.fffffffffffffp-55,  -0x1.ffffffffffffep-55,        0x1.8p-1, INEXACT)
T(RZ,                -0x1p-54,  -0x1.fffffffffffffp-55,        0x1.8p-1, INEXACT)
T(RZ,  -0x1.0000000000001p-54,                -0x1p-54,        0x1.cp-1, INEXACT)
T(RZ,  -0x1.0000000000002p-54,  -0x1.0000000000001p-54,        0x1.cp-1, INEXACT)
// Regression test: the bug found by Morten
T(RN,   -0x1.0a29d7d64ae2cp+2,   -0x1.f7ffd67be64dap-1,  -0x1.fffe7ep-6, INEXACT)
// Some difficult cases
T(RN,    0x1.4297ec53f6b7fp-1,    0x1.c16640ad39959p-1,         -0x1p-1, INEXACT)
T(RN,     0x1.accfbe46b4efp-1,    0x1.4f85c9783dce1p+0,   0x1.4f3d3p-55, INEXACT)
T(RN,    0x1.8bbe2fb45c151p-2,    0x1.e3186ba9d4d49p-2,         -0x1p-1, INEXACT)
T(RN,    0x1.4e88c5accfda5p-3,    0x1.6b68447b2f2fdp-3,   0x1.2cb8fp-55, INEXACT)
T(RN,    0x1.e923c188ea79bp-4,    0x1.03c5a420857cfp-3,  -0x1.e6348p-58, INEXACT)
T(RD,    0x1.4297ec53f6b7fp-1,    0x1.c16640ad39959p-1,         -0x1p-1, INEXACT)
T(RD,     0x1.accfbe46b4efp-1,     0x1.4f85c9783dcep+0,         -0x1p+0, INEXACT)
T(RD,    0x1.8bbe2fb45c151p-2,    0x1.e3186ba9d4d49p-2,         -0x1p-1, INEXACT)
T(RD,    0x1.4e88c5accfda5p-3,    0x1.6b68447b2f2fcp-3,         -0x1p+0, INEXACT)
T(RD,    0x1.e923c188ea79bp-4,    0x1.03c5a420857cfp-3,   -0x1.e634p-58, INEXACT)
T(RU,    0x1.4297ec53f6b7fp-1,    0x1.c16640ad3995ap-1,          0x1p-1, INEXACT)
T(RU,     0x1.accfbe46b4efp-1,    0x1.4f85c9783dce1p+0,   0x1.4f3d2p-55, INEXACT)
T(RU,    0x1.8bbe2fb45c151p-2,    0x1.e3186ba9d4d4ap-2,          0x1p-1, INEXACT)
T(RU,    0x1.4e88c5accfda5p-3,    0x1.6b68447b2f2fdp-3,   0x1.2cb8fp-55, INEXACT)
T(RU,    0x1.e923c188ea79bp-4,     0x1.03c5a420857dp-3,          0x1p+0, INEXACT)
T(RZ,    0x1.4297ec53f6b7fp-1,    0x1.c16640ad39959p-1,         -0x1p-1, INEXACT)
T(RZ,     0x1.accfbe46b4efp-1,     0x1.4f85c9783dcep+0,         -0x1p+0, INEXACT)
T(RZ,    0x1.8bbe2fb45c151p-2,    0x1.e3186ba9d4d49p-2,         -0x1p-1, INEXACT)
T(RZ,    0x1.4e88c5accfda5p-3,    0x1.6b68447b2f2fcp-3,         -0x1p+0, INEXACT)
T(RZ,    0x1.e923c188ea79bp-4,    0x1.03c5a420857cfp-3,   -0x1.e634p-58, INEXACT)
// Very worst case. 95 identical bits, it's probably our best. It is not a random one, though.
T(RZ,   0x1.7fffffffffffdp-49,   0x1.8000000000005p-49,         -0x1p+0, INEXACT) // 2.664535259100374513725358171900e-15
// One in five of the very worst cases computed by Lefevre and Muller.
// Rounding these values requires evaluating the function to at least 2^(-100).
// These worst cases have been selected thanks to the filterlists 5 script
// If you want the full list please contact Jean-Michel Muller
T(RZ,    0x1.005ae04256babp-1,    0x1.4cbb1357e7a3dp-1, -0x1.10f83cp-53, INEXACT) // 5.006933289508784801213892023952e-01
T(RZ,    0x1.0727af5fee8f6p-1,    0x1.5806551a5d846p-1, -0x1.05a628p-51, INEXACT) // 5.139746479610767249113223442691e-01
T(RZ,    0x1.12fcce02efb32p-1,    0x1.6c09c32841319p-1,         -0x1p+0, INEXACT) // 5.370849970421203156689671232016e-01
T(RZ,    0x1.41c9e095cd545p-1,    0x1.bfe3a84bbd0f1p-1, -0x1.dfb224p-51, INEXACT) // 6.284933264602520219810344315192e-01
T(RZ,     0x1.accfbe46b4efp-1,     0x1.4f85c9783dcep+0,         -0x1p+0, INEXACT) // 8.375224553405740124389922129922e-01
T(RZ,    0x1.4b7b1868ab96p-10,   0x1.4bb0c524bb555p-10,         -0x1p+0, INEXACT) // 1.264499058531841357844172080149e-03
T(RN,   0x1.74c94bf209126p-10,   0x1.750d2f63268fdp-10,         -0x1p-1, INEXACT) // 1.422066936819518703088993660799e-03
T(RZ,   0x1.9fd791855c814p-10,   0x1.a02c0c886fb74p-10, -0x1.029b64p-51, INEXACT) // 1.586311585324744373448613288247e-03
T(RZ,   0x1.a77eb3f6d31c5p-10,   0x1.a7d65289493fap-10,         -0x1p+0, INEXACT) // 1.615504964962531349662033797188e-03
T(RN,   0x1.acf4bcbf84d75p-10,    0x1.ad4ea1b49c9ap-10,         -0x1p-1, INEXACT) // 1.636337299605409136352140997417e-03
T(RN,   0x1.d68e0ce210935p-10,   0x1.d6fa3b3048628p-10,         -0x1p-1, INEXACT) // 1.795024429626379926586143831457e-03
T(RN,   0x1.abccf85927836p-11,   0x1.abf9a9cc4b305p-11,          0x1p-1, INEXACT) // 8.159650125383391666006316356174e-04
T(RN,   0x1.42391da930c99p-12,   0x1.4245ca9c2261dp-12,          0x1p-1, INEXACT) // 3.072959030527372078535341959338e-04
T(RZ,    0x1.581fc7756599p-12,   0x1.582e3c886aba8p-12,         -0x1p+0, INEXACT) // 3.281823513473719824973251490974e-04
T(RZ,   0x1.9b2ebd6ce08aep-12,   0x1.9b43619696f09p-12, -0x1.a49728p-51, INEXACT) // 3.921342638976238427137022135582e-04
T(RN,   0x1.bbf2d53e60743p-12,   0x1.bc0ae52f8e3cap-12,         -0x1p-1, INEXACT) // 4.233823455238492033773922695872e-04
T(RN,   0x1.26f951de92a8bp-13,   0x1.26fea1754f931p-13,         -0x1p-1, INEXACT) // 1.406545188323459134090848143828e-04
T(RZ,   0x1.badf1efca64d6p-13,   0x1.baeb17d0c6b9ep-13,         -0x1p+0, INEXACT) // 2.111776192535222136485717481236e-04
T(RZ,   0x1.c6a980ffb27b4p-13,   0x1.c6b61f320bb96p-13, -0x1.aaefbep-51, INEXACT) // 2.167997954443647229752500926736e-04
T(RN,   0x1.e1de96fada839p-13,   0x1.e1ecc35ad2463p-13,          0x1p-1, INEXACT) // 2.297732788421618006519803190102e-04
T(RN,   0x1.6a6b36be58808p-14,   0x1.6a6f38ecb0f3ap-14,          0x1p-1, INEXACT) // 8.640737630608030534623553720053e-05
T(RZ,   0x1.655300604782ap-14,   0x1.6556e5e8bbe3cp-14, -0x1.43f796p-51, INEXACT) // 8.519273388116256639536472139440e-05
T(RN,   0x1.a253342489ff1p-14,   0x1.a2588b57cf6fep-14,          0x1p-1, INEXACT) // 9.973645553229528381514873425218e-05
T(RN,   0x1.27b366256f194p-15,   0x1.27b4bbb56940ep-15,          0x1p-1, INEXACT) // 3.525027959081213448956637623866e-05
T(RN,   0x1.dec504595f456p-15,   0x1.dec883c20f85dp-15,         -0x1p-1, INEXACT) // 5.707378358985801247976049621613e-05
T(RN,   0x1.0428907e1378fp-16,   0x1.042914af76376p-16,         -0x1p-1, INEXACT) // 1.550665228249693011904584982741e-05
T(RN,   0x1.2f9856c3059efp-16,   0x1.2f990ac848cd1p-16,         -0x1p-1, INEXACT) // 1.809567653418027235469843494453e-05
T(RZ,   0x1.450e49b4a3789p-16,   0x1.450f18139ec99p-16,         -0x1p+0, INEXACT) // 1.937483621588341402655099321439e-05
T(RZ,   0x1.31b6a89db0407p-16,   0x1.31b75f2858f83p-16, -0x1.0b76b4p-53, INEXACT) // 1.822194518897107413913337425893e-05
T(RN,   0x1.51fce10251a48p-16,   0x1.51fdc02094ef7p-16,         -0x1p-1, INEXACT) // 2.014564325605376041324057201365e-05
T(RN,   0x1.7cbe2ad7e2c54p-16,   0x1.7cbf45fafd5dap-16,          0x1p-1, INEXACT) // 2.269404180270066112307808525728e-05
T(RZ,    0x1.adc6bb5b1c2ep-16,   0x1.adc8241dbb2acp-16,         -0x1p+0, INEXACT) // 2.561666347528329234356503363301e-05
T(RZ,   0x1.0b0c62f2b5cc6p-17,    0x1.0b0ca89777a8p-17, -0x1.351824p-51, INEXACT) // 7.958662057756793055699959249516e-06
T(RZ,   0x1.c8d9b5668584ep-17,   0x1.c8da8138d5fccp-17, -0x1.928a88p-51, INEXACT) // 1.361520362501088989687879349244e-05
T(RZ,   0x1.dbe376499989cp-17,   0x1.dbe4537356d33p-17,         -0x1p+0, INEXACT) // 1.418258320313682600789448318146e-05
T(RZ,   0x1.9149d0f28bbf7p-18,   0x1.914a1f93a0c0ep-18,         -0x1p+0, INEXACT) // 5.979662307128110624915209164731e-06
T(RZ,   0x1.d8b91fb7c7038p-18,   0x1.d8b98cd53d288p-18, -0x1.041d6cp-51, INEXACT) // 7.044123712576142142937490886467e-06
T(RN,   0x1.b8c6eb5ffac92p-18,    0x1.b8c74a3d94dbp-18,         -0x1p-1, INEXACT) // 6.568089560214601817689401841438e-06
T(RN,   0x1.67ba80988725ap-19,   0x1.67baa03052c7dp-19,         -0x1p-1, INEXACT) // 2.680186366411837655982387113029e-06
T(RZ,   0x1.84709ffc724e4p-19,   0x1.8470c4d2ce0a9p-19,  -0x1.75431p-51, INEXACT) // 2.894103088933566825355532536879e-06
T(RN,   0x1.99213264807dcp-19,   0x1.99215b4234ab9p-19,         -0x1p-1, INEXACT) // 3.048253619520621701221956001415e-06
T(RZ,   0x1.b7f934085acb6p-19,   0x1.b7f9634ae85e7p-19, -0x1.ac349cp-53, INEXACT) // 3.278057651259065677351849793508e-06
T(RZ,   0x1.cf8eeb2d2568bp-19,   0x1.cf8f1fa38dc57p-19,  -0x1.d738fp-51, INEXACT) // 3.453778296756361789512359758425e-06
T(RZ,   0x1.f0077055498f1p-19,   0x1.f007ac671ba0ap-19,         -0x1p+0, INEXACT) // 3.695704473688427787130385618330e-06
T(RZ,   0x1.e98f167abea1ap-19,   0x1.e98f50fe0288dp-19,         -0x1p+0, INEXACT) // 3.647498315271071024038385816057e-06
T(RZ,    0x1.a3a7add74f25ap-2,    0x1.0359f11a22a8dp-1, -0x1.1318aap-51, INEXACT) // 4.098193323768889451130803536216e-01
T(RZ,    0x1.bcab27d05abdep-2,    0x1.166ce703b05e9p-1,  -0x1.dfe7bp-53, INEXACT) // 4.342466565055341787271458997566e-01
T(RN,   0x1.1b990cab42256p-20,   0x1.1b99167ca04b7p-20,         -0x1p-1, INEXACT) // 1.056484317642688086023297286409e-06
T(RN,   0x1.11e54952cc21ep-20,   0x1.11e5527b22f41p-20,         -0x1p-1, INEXACT) // 1.020340808021689558477860734764e-06
T(RZ,   0x1.3763a907b12f8p-20,   0x1.3763b4ddcbd83p-20, -0x1.9ff9c8p-51, INEXACT) // 1.160015530675047266680015300988e-06
T(RN,   0x1.a4406cb34c9d4p-20,   0x1.a440824269011p-20,         -0x1p-1, INEXACT) // 1.565559426830292909422776698181e-06
T(RZ,   0x1.e73856741e035p-20,    0x1.e738736e5a54p-20,         -0x1p+0, INEXACT) // 1.815036196920968968257785632059e-06
T(RZ,   0x1.6a2e7751f12f3p-21,   0x1.6a2e7f538f14fp-21, -0x1.230fccp-51, INEXACT) // 6.746156293526846286067052103907e-07
T(RZ,   0x1.7170f38ad676ap-21,   0x1.7170fbdf71d66p-21, -0x1.749c8cp-52, INEXACT) // 6.881378892084896807648840624805e-07
T(RN,   0x1.afb5c5e4486f4p-21,   0x1.afb5d1445ee81p-21,          0x1p-1, INEXACT) // 8.041226320679659189986313722054e-07
T(RZ,   0x1.d610b08165e99p-21,   0x1.d610bdfdeb506p-21, -0x1.0ee666p-52, INEXACT) // 8.755646520473109463056815733595e-07
T(RZ,   0x1.efbd648cef1d2p-21,   0x1.efbd738ce7467p-21, -0x1.c68228p-51, INEXACT) // 9.233873626761688504762043763763e-07
T(RZ,   0x1.0f6170091b49bp-22,   0x1.0f6172487a2d7p-22, -0x1.02ccf8p-51, INEXACT) // 2.527428937863281450681453548651e-07
T(RN,   0x1.371a1ec60762fp-22,   0x1.371a21ba285aap-22,          0x1p-1, INEXACT) // 2.897363454728492891089781154784e-07
T(RZ,   0x1.ef8e3ded3507fp-22,   0x1.ef8e456bc3e05p-22, -0x1.31dba8p-51, INEXACT) // 4.615221474550486239562076869886e-07
T(RZ,   0x1.9fed42c04a907p-22,   0x1.9fed4807d0d07p-22,         -0x1p+0, INEXACT) // 3.873620180334250951617711036107e-07
T(RN,   0x1.6eb68e8c7b02ap-22,   0x1.6eb692a7180e1p-22,          0x1p-1, INEXACT) // 3.415282001917601564412057570108e-07
T(RN,   0x1.5540c0f13fd48p-23,   0x1.5540c2b825688p-23,          0x1p-1, INEXACT) // 1.589082852318328754247451009562e-07
T(RN,   0x1.a31972381bd0cp-23,   0x1.a31974e638221p-23,         -0x1p-1, INEXACT) // 1.951583656930781513543448311976e-07
T(RZ,   0x1.08e89d859a836p-24,   0x1.08e89e0eaacfbp-24, -0x1.b7a0cap-52, INEXACT) // 6.167885232560242796691471391796e-08
T(RN,   0x1.1a4d6f93a29efp-24,   0x1.1a4d702f49f7dp-24,          0x1p-1, INEXACT) // 6.572866900249659935210640301570e-08
T(RZ,   0x1.40174397fd869p-24,   0x1.401744601a9c7p-24,  -0x1.6e236p-51, INEXACT) // 7.452696448848514941270014056221e-08
T(RZ,   0x1.ad800b3a6a7fdp-24,   0x1.ad800ca2b5b37p-24,  -0x1.3345ep-55, INEXACT) // 1.000008013398725021377989982847e-07
T(RZ,   0x1.81b0f381cff0cp-24,   0x1.81b0f4a45accbp-24, -0x1.03fcacp-51, INEXACT) // 8.980073398518289150930789081773e-08
T(RN,   0x1.725d1832dbe89p-24,   0x1.725d193ec486fp-24,         -0x1p-1, INEXACT) // 8.623200713013558743784897154053e-08
T(RZ,   0x1.cdd26cdb8d888p-25,    0x1.cdd26dabd56bp-25, -0x1.d08d66p-51, INEXACT) // 5.376315367589579226827883363937e-08
T(RZ,   0x1.d7a90e8ea82c5p-25,   0x1.d7a90f67e80d5p-25,         -0x1p+0, INEXACT) // 5.490849474166313689473215031191e-08
T(RN,   0x1.f21ac1d3378f2p-25,   0x1.f21ac2c58296bp-25,          0x1p-1, INEXACT) // 5.798699800341913557350355607270e-08
T(RZ,   0x1.fad44fd7ab54bp-25,   0x1.fad450d28653fp-25, -0x1.fa73ecp-51, INEXACT) // 5.900270111151337939155666115730e-08
T(RZ,   0x1.b0e54beaa5f54p-26,    0x1.b0e54c4626cbp-26,  -0x1.62c1ep-54, INEXACT) // 2.519784551377563473767976680653e-08
T(RN,   0x1.709790c9cef04p-26,   0x1.7097910c25739p-26,          0x1p-1, INEXACT) // 2.145488123900374738431499075167e-08
T(RZ,   0x1.97ef8c7a6a15ap-27,   0x1.97ef8ca30aceap-27,         -0x1p+0, INEXACT) // 1.187249253495058302790544316630e-08
T(RN,   0x1.bddfe561dbef3p-27,   0x1.bddfe5926531bp-27,          0x1p-1, INEXACT) // 1.297665858424598428062944399436e-08
T(RZ,   0x1.e76ee51afcfbap-27,   0x1.e76ee554fe6d6p-27, -0x1.059474p-51, INEXACT) // 1.418617272782483634263233425888e-08
T(RZ,   0x1.10d3ed6d5160fp-28,   0x1.10d3ed7667793p-28, -0x1.95161cp-51, INEXACT) // 3.970167622884932487740220359010e-09
T(RZ,   0x1.be4c1b571a289p-28,   0x1.be4c1b6f6a92cp-28, -0x1.837914p-51, INEXACT) // 6.494480362438469762460236230301e-09
T(RZ,   0x1.cfdf2a63e8c69p-28,   0x1.cfdf2a7e2d0e8p-28, -0x1.dfbee4p-51, INEXACT) // 6.750222245670706013815512647408e-09
T(RN,   0x1.9d6f375a07c12p-28,   0x1.9d6f376ee5417p-28,          0x1p-1, INEXACT) // 6.016262899351159692087286881990e-09
T(RZ,   0x1.b5b7b347eb1a5p-28,   0x1.b5b7b35f4e7fcp-28, -0x1.6878e8p-51, INEXACT) // 6.369629108811366297460832545290e-09
T(RZ,   0x1.fa3ade2dded37p-28,   0x1.fa3ade4d27398p-28,         -0x1p+0, INEXACT) // 7.366615357536089054625238293833e-09
T(RZ,   0x1.668e898383c47p-29,   0x1.668e898b5c905p-29, -0x1.8f4708p-54, INEXACT) // 2.608843975707637591842709778411e-09
T(RN,    0x1.c24b71882cff3p-3,    0x1.f7a274060d907p-3,          0x1p-1, INEXACT) // 2.198704595263048788833515345686e-01
T(RZ,    0x1.fde31a71ddba9p-3,    0x1.217c79b0566b5p-2, -0x1.066766p-52, INEXACT) // 2.489683214186844406601295531800e-01
T(RN,   0x1.f75b20f5ac212p-30,   0x1.f75b20fd678fap-30,          0x1p-1, INEXACT) // 1.831198357374760117422428918580e-09
T(RN,   0x1.816060fba05b5p-31,   0x1.816060fde47e5p-31,         -0x1p-1, INEXACT) // 7.009957332081317687745861915295e-10
T(RZ,   0x1.fcffdbc85be3ep-31,   0x1.fcffdbcc4fec5p-31,  -0x1.96b55p-55, INEXACT) // 9.258646011715036043020402617052e-10
T(RN,   0x1.efc075bb4e78fp-31,   0x1.efc075bf0e82dp-31,          0x1p-1, INEXACT) // 9.017672645180203612081538623233e-10
T(RN,   0x1.079df58d66228p-32,   0x1.079df58deddd8p-32,          0x1p-1, INEXACT) // 2.397582903371179136683931512131e-10
T(RZ,   0x1.3bec333a0f929p-32,   0x1.3bec333ad2822p-32, -0x1.07c2dcp-51, INEXACT) // 2.873299824013314191185535394001e-10
T(RZ,   0x1.48a851b06182ap-32,   0x1.48a851b1347a7p-32,         -0x1p+0, INEXACT) // 2.989122517419990964741322775399e-10
T(RZ,   0x1.aa2884ae7de9ap-32,   0x1.aa2884afe09f1p-32,  -0x1.0a7c6p-55, INEXACT) // 3.875886928296320111934657270220e-10
T(RZ,    0x1.01ffffffea55p-33,   0x1.020000002b55fp-33,         -0x1p+0, INEXACT) // 1.173248165264135572621242168062e-10
T(RZ,   0x1.007fffffea955p-33,   0x1.008000002ad55p-33,         -0x1p+0, INEXACT) // 1.166426955001104601102603458055e-10
T(RZ,     0x1.07ffffffe95p-33,   0x1.080000002d5ffp-33,         -0x1p+0, INEXACT) // 1.200533006316243949059311638822e-10
T(RZ,   0x1.097fffffe90ddp-33,   0x1.098000002de45p-33,         -0x1p+0, INEXACT) // 1.207354216579267165759707664194e-10
T(RZ,   0x1.187fffffe6635p-33,   0x1.1880000033395p-33,         -0x1p+0, INEXACT) // 1.275566319209414029762998386941e-10
T(RZ,   0x1.10ffffffe7bd4p-33,   0x1.1100000030857p-33,         -0x1p+0, INEXACT) // 1.241460267894359984806959737154e-10
T(RZ,      0x1.1fffffffe5p-33,   0x1.2000000035fffp-33,         -0x1p+0, INEXACT) // 1.309672370524429300627823613556e-10
T(RZ,   0x1.16ffffffe6a94p-33,   0x1.1700000032ad7p-33,         -0x1p+0, INEXACT) // 1.268745108946406322699087730838e-10
T(RZ,   0x1.1e7fffffe547dp-33,   0x1.1e80000035705p-33,         -0x1p+0, INEXACT) // 1.302851160261429348382155642087e-10
T(RZ,   0x1.0f7fffffe8015p-33,   0x1.0f8000002ffd5p-33,         -0x1p+0, INEXACT) // 1.234639057631344522924806396416e-10
T(RN,   0x1.22be606863db3p-33,   0x1.22be6068b6682p-33,         -0x1p-1, INEXACT) // 1.322149085198737521897341807607e-10
T(RZ,   0x1.277fffffe3935p-33,   0x1.2780000038d95p-33,         -0x1p+0, INEXACT) // 1.343778421839405797401435416999e-10
T(RZ,   0x1.2d7fffffe268dp-33,   0x1.2d8000003b2e5p-33,         -0x1p+0, INEXACT) // 1.371063262891359077474651195070e-10
T(RZ,   0x1.2effffffe21d4p-33,   0x1.2f0000003bc57p-33,         -0x1p+0, INEXACT) // 1.377884473154343520083833797270e-10
T(RZ,   0x1.52ffffffda974p-33,   0x1.530000004ad17p-33,         -0x1p+0, INEXACT) // 1.541593519465504853609655172011e-10
T(RZ,   0x1.547fffffda425p-33,   0x1.548000004b7b5p-33,         -0x1p+0, INEXACT) // 1.548414729728450522127624351039e-10
T(RZ,   0x1.6affffffd51b4p-33,   0x1.6b00000055c97p-33,         -0x1p+0, INEXACT) // 1.650732883672449434259337605233e-10
T(RZ,   0x1.367fffffe09ddp-33,   0x1.368000003ec45p-33,         -0x1p+0, INEXACT) // 1.411990524469242468675018754368e-10
T(RZ,   0x1.3c7fffffdf645p-33,   0x1.3c80000041375p-33,         -0x1p+0, INEXACT) // 1.439275365521133710202293055363e-10
T(RZ,   0x1.4cffffffdbe74p-33,   0x1.4d00000048317p-33,         -0x1p+0, INEXACT) // 1.514308678413706669901293086630e-10
T(RZ,   0x1.70ffffffd3ad4p-33,   0x1.7100000058a57p-33,         -0x1p+0, INEXACT) // 1.678017724724123540875816736463e-10
T(RZ,    0x1.61ffffffd735p-33,   0x1.620000005195fp-33,         -0x1p+0, INEXACT) // 1.609805622094891745425162800582e-10
T(RZ,    0x1.43ffffffddd4p-33,   0x1.440000004457fp-33,         -0x1p+0, INEXACT) // 1.473381416835962865429293850751e-10
T(RZ,    0x1.25ffffffe3ddp-33,   0x1.260000003845fp-33,         -0x1p+0, INEXACT) // 1.336957211576413599974010130165e-10
T(RZ,   0x1.34ffffffe0eb4p-33,   0x1.350000003e297p-33,         -0x1p+0, INEXACT) // 1.405169314206265780884078836802e-10
T(RZ,   0x1.4b7fffffdc3a5p-33,   0x1.4b800000478b5p-33,         -0x1p+0, INEXACT) // 1.507487468150753246565081222967e-10
T(RZ,    0x1.3dffffffdf15p-33,   0x1.3e00000041d5fp-33,         -0x1p+0, INEXACT) // 1.446096575784102643174990288294e-10
T(RZ,   0x1.457fffffdd82dp-33,   0x1.4580000044fa5p-33,         -0x1p+0, INEXACT) // 1.480202627098924043583748399048e-10
T(RZ,   0x1.5a7fffffd8eadp-33,   0x1.5a8000004e2a5p-33,         -0x1p+0, INEXACT) // 1.575699570780217686563015697882e-10
T(RZ,   0x1.727fffffd350dp-33,   0x1.72800000595e5p-33,         -0x1p+0, INEXACT) // 1.684838934987038190120815176954e-10
T(RZ,    0x1.5bffffffd894p-33,   0x1.5c0000004ed7fp-33,         -0x1p+0, INEXACT) // 1.582520781043155600262742192276e-10
T(RZ,   0x1.637fffffd6dc5p-33,   0x1.6380000052475p-33,         -0x1p+0, INEXACT) // 1.616626832357821904306646610341e-10
T(RZ,   0x1.697fffffd575dp-33,   0x1.6980000055145p-33,         -0x1p+0, INEXACT) // 1.643911673409527030196096480109e-10
T(RZ,   0x1.a1283415c820ep-33,   0x1.a12834167211ep-33, -0x1.ae538ep-52, INEXACT) // 1.897010610061101118173145713613e-10
T(RZ,   0x1.c3bb972406294p-33,   0x1.c3bb9724cd70dp-33,         -0x1p+0, INEXACT) // 2.054242827281769450257497060480e-10
T(RN,   0x1.eff9e72fe698cp-33,   0x1.eff9e730d6d2ep-33,          0x1p-1, INEXACT) // 2.255438557246551296427447616392e-10
T(RZ,   0x1.01fffffff52a8p-34,   0x1.0200000015aafp-34,         -0x1p+0, INEXACT) // 5.866240826378032498829106396719e-11
T(RZ,   0x1.04fffffff4e9ap-34,   0x1.05000000162cbp-34,         -0x1p+0, INEXACT) // 5.934452929009660533116749884646e-11
T(RN,   0x1.095702237abdcp-34,   0x1.095702239d1e6p-34,         -0x1p-1, INEXACT) // 6.033130293470062662984341451641e-11
T(RZ,   0x1.10fffffff3deap-34,   0x1.110000001842bp-34,         -0x1p+0, INEXACT) // 6.207301339536017573902470143666e-11
T(RZ,    0x1.13fffffff39ap-34,   0x1.1400000018cbfp-34,         -0x1p+0, INEXACT) // 6.275513442167568060007686785249e-11
T(RZ,   0x1.2efffffff10eap-34,   0x1.2f0000001de2bp-34,         -0x1p+0, INEXACT) // 6.889422365850824501312794942393e-11
T(RZ,   0x1.22fffffff237ap-34,   0x1.230000001b90bp-34,         -0x1p+0, INEXACT) // 6.616573955325087845986489454129e-11
T(RZ,   0x1.4cffffffedf3ap-34,   0x1.4d0000002418bp-34,         -0x1p+0, INEXACT) // 7.571543392164080465074582814230e-11
T(RZ,   0x1.5effffffebf2ap-34,   0x1.5f000000281abp-34,         -0x1p+0, INEXACT) // 7.980816007951289580780357812425e-11
T(RZ,   0x1.31fffffff0c28p-34,   0x1.320000001e7afp-34,         -0x1p+0, INEXACT) // 6.957634468482219891053157891287e-11
T(RZ,   0x1.3dffffffef8a8p-34,   0x1.3e00000020eafp-34,         -0x1p+0, INEXACT) // 7.230482879007646353649755994173e-11
T(RZ,     0x1.1ffffffff28p-34,   0x1.200000001afffp-34,         -0x1p+0, INEXACT) // 6.548361852693614908063699658891e-11
T(RZ,   0x1.40ffffffef3aap-34,   0x1.41000000218abp-34,         -0x1p+0, INEXACT) // 7.298694981638964195207692096722e-11
T(RZ,     0x1.4fffffffedap-34,   0x1.5000000024bffp-34,         -0x1p+0, INEXACT) // 7.639755494795320758450092070435e-11
T(RN,   0x1.38de271070a65p-34,   0x1.38de2710a0722p-34,          0x1p-1, INEXACT) // 7.113789787869701429669294351813e-11
T(RZ,    0x1.97ffffffe4e8p-34,   0x1.98000000362ffp-34,         -0x1p+0, INEXACT) // 9.276845957940434908516703438677e-11
T(RZ,   0x1.6affffffea8dap-34,   0x1.6b0000002ae4bp-34,         -0x1p+0, INEXACT) // 8.253664418475785465187833759177e-11
T(RZ,   0x1.f1ffffffd7a28p-34,   0x1.f200000050bafp-34,         -0x1p+0, INEXACT) // 1.132320903685926479054681854117e-10
T(RZ,   0x1.a6ffffffe2e0ap-34,   0x1.a70000003a3ebp-34,         -0x1p+0, INEXACT) // 9.617906471094542574468724868399e-11
T(RZ,   0x1.b8ffffffe058ap-34,   0x1.b90000003f4ebp-34,         -0x1p+0, INEXACT) // 1.002717908687895995560713339819e-10
T(RZ,   0x1.88ffffffe6dcap-34,   0x1.890000003246bp-34,         -0x1p+0, INEXACT) // 8.935785444785939501652547777233e-11
T(RZ,   0x1.9affffffe481ap-34,   0x1.9b00000036fcbp-34,         -0x1p+0, INEXACT) // 9.345058060571287460980078463159e-11
T(RZ,   0x1.6dffffffea328p-34,   0x1.6e0000002b9afp-34,         -0x1p+0, INEXACT) // 8.321876521106870662198489322693e-11
T(RZ,   0x1.7cffffffe85fap-34,   0x1.7d0000002f40bp-34,         -0x1p+0, INEXACT) // 8.662937034262064002704486601237e-11
T(RZ,    0x1.8bffffffe67ap-34,   0x1.8c000000330bfp-34,         -0x1p+0, INEXACT) // 9.003997547416869602298349648060e-11
T(RZ,   0x1.a9ffffffe2768p-34,   0x1.aa0000003b12fp-34,         -0x1p+0, INEXACT) // 9.686118573725317578749673046536e-11
T(RZ,    0x1.c7ffffffde28p-34,   0x1.c800000043affp-34,         -0x1p+0, INEXACT) // 1.036823960003221459155245951812e-10
T(RZ,    0x1.d3ffffffdc5ap-34,   0x1.d4000000474bfp-34,         -0x1p+0, INEXACT) // 1.064108801055453912685198376723e-10
T(RZ,   0x1.d6ffffffdbe4ap-34,   0x1.d70000004836bp-34,         -0x1p+0, INEXACT) // 1.070930011318508148658565140633e-10
T(RZ,   0x1.b5ffffffe0c68p-34,   0x1.b60000003e72fp-34,         -0x1p+0, INEXACT) // 9.958966984248262499508612066398e-11
T(RZ,   0x1.c4ffffffde99ap-34,   0x1.c500000042ccbp-34,         -0x1p+0, INEXACT) // 1.030002749740159468363636503267e-10
T(RZ,   0x1.e5ffffffd98e8p-34,   0x1.e60000004ce2fp-34,         -0x1p+0, INEXACT) // 1.105036062633756064070670906282e-10
T(RN,   0x1.e10ba450e0138p-34,   0x1.e10ba45151111p-34,         -0x1p-1, INEXACT) // 1.093770779361761086321169770999e-10
T(RZ,   0x1.e2ffffffda07ap-34,   0x1.e30000004bf0bp-34,         -0x1p+0, INEXACT) // 1.098214852370709582915546827006e-10
T(RN,   0x1.e53feae59a2c3p-34,   0x1.e53feae60d25ap-34,          0x1p-1, INEXACT) // 1.103330027926859625004644019823e-10
T(RZ,    0x1.5bffffffec4ap-34,   0x1.5c000000276bfp-34,         -0x1p+0, INEXACT) // 7.912603905320126835587275402565e-11
T(RZ,   0x1.79ffffffe8be8p-34,   0x1.7a0000002e82fp-34,         -0x1p+0, INEXACT) // 8.594724931631056353876257884066e-11
T(RZ,   0x1.f4ffffffd725ap-34,   0x1.f500000051b4bp-34,         -0x1p+0, INEXACT) // 1.139142113948965205391563248758e-10
T(RN,   0x1.9327892d5759dp-35,   0x1.9327892d7f082p-35,         -0x1p-1, INEXACT) // 4.583335304535563948131400182231e-11
T(RZ,   0x1.01fffffffd4aap-36,   0x1.02000000056abp-36,         -0x1p+0, INEXACT) // 1.466560206605262118905319516006e-11
T(RZ,     0x1.1ffffffffcap-36,   0x1.2000000006bffp-36,         -0x1p+0, INEXACT) // 1.637090463186804052939283963056e-11
T(RZ,   0x1.3dfffffffbe2ap-36,   0x1.3e000000083abp-36,         -0x1p+0, INEXACT) // 1.807620719768249051745214852175e-11
T(RN,   0x1.68f8e887525d9p-36,   0x1.68f8e88762458p-36,          0x1p-1, INEXACT) // 2.051889953832339597598697276729e-11
T(RZ,   0x1.5bfffffffb128p-36,   0x1.5c00000009dafp-36,         -0x1p+0, INEXACT) // 1.978150976349597115323112183363e-11
T(RZ,   0x1.79fffffffa2fap-36,   0x1.7a0000000ba0bp-36,         -0x1p+0, INEXACT) // 2.148681232930848243672975956621e-11
T(RN,   0x1.95aef19a6bb93p-36,   0x1.95aef19a7fd05p-36,          0x1p-1, INEXACT) // 2.306042995726105936178128527223e-11
T(RZ,   0x1.b5fffffff831ap-36,   0x1.b60000000f9cbp-36,         -0x1p+0, INEXACT) // 2.489741746093059694688602829345e-11
T(RZ,    0x1.97fffffff93ap-36,   0x1.980000000d8bfp-36,         -0x1p+0, INEXACT) // 2.319211489512002436794806171949e-11
T(RZ,   0x1.d3fffffff7168p-36,   0x1.d400000011d2fp-36,         -0x1p+0, INEXACT) // 2.660272002674020017354365928811e-11
T(RZ,   0x1.f1fffffff5e8ap-36,   0x1.f2000000142ebp-36,         -0x1p+0, INEXACT) // 2.830802259254883404792095470346e-11
T(RN,   0x1.85f1e2dccad35p-36,   0x1.85f1e2dcdd632p-36,          0x1p-1, INEXACT) // 2.216579945846740163251454060499e-11
T(RZ,   0x1.0dfffffffe845p-37,   0x1.0e00000002f75p-37,         -0x1p+0, INEXACT) // 7.673861546199267315569744349366e-12
T(RZ,   0x1.19fffffffe61dp-37,   0x1.1a000000033c5p-37,         -0x1p+0, INEXACT) // 8.014922059363223600689975264841e-12
T(RZ,   0x1.2bfffffffe2b4p-37,   0x1.2c00000003a97p-37,         -0x1p+0, INEXACT) // 8.526512829109085326949296469606e-12
T(RZ,   0x1.55fffffffd9edp-37,   0x1.5600000004c25p-37,         -0x1p+0, INEXACT) // 9.720224625182423414922928494635e-12
T(RZ,    0x1.37fffffffe05p-37,   0x1.3800000003f5fp-37,         -0x1p+0, INEXACT) // 8.867573342272944676841493827151e-12
T(RZ,   0x1.4148f08916f8fp-37,   0x1.4148f0891d45cp-37,         -0x1p+0, INEXACT) // 9.131466648584592341143870588643e-12
T(RZ,   0x1.73fffffffd2f4p-37,   0x1.7400000005a17p-37,         -0x1p+0, INEXACT) // 1.057287590809165981493427926729e-11
T(RZ,   0x1.85fffffffce7dp-37,   0x1.8600000006305p-37,         -0x1p+0, INEXACT) // 1.108446667783708533266744946137e-11
T(RZ,   0x1.a3fffffffc694p-37,   0x1.a4000000072d7p-37,         -0x1p+0, INEXACT) // 1.193711796074593399176666600230e-11
T(RN,   0x1.afe1c60db945ep-37,   0x1.afe1c60dc4a85p-37,          0x1p-1, INEXACT) // 1.227482267461914424013486921320e-11
T(RZ,   0x1.b1ba5fdf09c34p-37,   0x1.b1ba5fdf153e9p-37,         -0x1p+0, INEXACT) // 1.232729190914681615383629394667e-11
T(RN,   0x1.80d46fe77a36bp-37,   0x1.80d46fe78340ap-37,         -0x1p-1, INEXACT) // 1.093752168011161407811498738566e-11
T(RZ,    0x1.67fffffffd5dp-37,   0x1.680000000545fp-37,         -0x1p+0, INEXACT) // 1.023181539492799433549814902561e-11
T(RZ,   0x1.91fffffffcb65p-37,   0x1.9200000006935p-37,         -0x1p+0, INEXACT) // 1.142552719100065387687554614512e-11
T(RZ,   0x1.c1fffffffbe15p-37,   0x1.c2000000083d5p-37,         -0x1p+0, INEXACT) // 1.278976924365454031279579864841e-11
T(RN,   0x1.9c0bce1f40b19p-37,   0x1.9c0bce1f4b0e6p-37,         -0x1p-1, INEXACT) // 1.171105492185670062735711629842e-11
T(RZ,    0x1.affffffffc34p-37,   0x1.b00000000797fp-37,         -0x1p+0, INEXACT) // 1.227817847390940560074672912813e-11
T(RZ,   0x1.fdfffffffab55p-37,   0x1.fe0000000a955p-37,         -0x1p+0, INEXACT) // 1.449507180947102594064381225615e-11
T(RZ,   0x1.cdfffffffba85p-37,   0x1.ce00000008af5p-37,         -0x1p+0, INEXACT) // 1.313082975681791498654782821630e-11
T(RZ,   0x1.49fffffffdc8dp-37,   0x1.4a000000046e5p-37,         -0x1p+0, INEXACT) // 9.379164112018661000258764695021e-12
T(RZ,     0x1.dffffffffb5p-37,   0x1.e0000000095ffp-37,         -0x1p+0, INEXACT) // 1.364242052656290429575484739969e-11
T(RZ,   0x1.ebfffffffb134p-37,   0x1.ec00000009d97p-37,         -0x1p+0, INEXACT) // 1.398348103972618203427884340965e-11
T(RZ,   0x1.fffeffffbaaa9p-37,   0x1.fffeffffcaaa8p-37, -0x1.3f1cb2p-52, INEXACT) // 1.455180420560557708524528013212e-11
T(RN,   0x1.18ce54e43bc89p-38,   0x1.18ce54e43e309p-38,         -0x1p-1, INEXACT) // 3.990493025328016717818473197002e-12
T(RZ,   0x1.37ffffffff028p-38,   0x1.3800000001fafp-38,         -0x1p+0, INEXACT) // 4.433786671139748749128281171632e-12
T(RN,   0x1.483cdb228d0a4p-38,    0x1.483cdb229054p-38,          0x1p-1, INEXACT) // 4.664538532981070104301153949538e-12
T(RZ,   0x1.4148f0891805cp-38,   0x1.4148f0891b2c2p-38,         -0x1p+0, INEXACT) // 4.565733324295770490703371399819e-12
T(RZ,   0x1.54a57d5f4c474p-38,   0x1.54a57d5f4fd1dp-38,  -0x1.a3f63p-51, INEXACT) // 4.840877128896664723033961592106e-12
T(RN,   0x1.8387d84827defp-38,   0x1.8387d8482c743p-38,         -0x1p-1, INEXACT) // 5.507141678851540396603104706463e-12
T(RZ,   0x1.ebfffffffd89ap-38,   0x1.ec00000004ecbp-38,         -0x1p+0, INEXACT) // 6.991740519871238423055642248898e-12
T(RZ,   0x1.73fffffffe97ap-38,   0x1.7400000002d0bp-38,         -0x1p+0, INEXACT) // 5.286437954050487645174152092214e-12
T(RZ,    0x1.affffffffe1ap-38,   0x1.b000000003cbfp-38,         -0x1p+0, INEXACT) // 6.139089236960984203149939117969e-12
T(RN,   0x1.bfd7fe36b08dep-38,   0x1.bfd7fe36b6acdp-38,          0x1p-1, INEXACT) // 6.364242079004326352489170501503e-12
T(RZ,   0x1.07ffffffffa54p-39,   0x1.0800000000b57p-39,         -0x1p+0, INEXACT) // 1.875832822406078032570165040926e-12
T(RZ,     0x1.7fffffffff4p-39,   0x1.80000000017ffp-39,         -0x1p+0, INEXACT) // 2.728484105317543942826287645988e-12
T(RZ,   0x1.2f50a501093f6p-39,   0x1.2f50a5010aa6cp-39, -0x1.db76f2p-52, INEXACT) // 2.155182825177015163085061367008e-12
T(RZ,   0x1.43ffffffff775p-39,   0x1.4400000001115p-39,         -0x1p+0, INEXACT) // 2.302158463861841279956986830310e-12
T(RZ,   0x1.bbfffffffeff5p-39,   0x1.bc00000002015p-39,         -0x1p+0, INEXACT) // 3.154809746773186021178067487959e-12
T(RZ,   0x1.da3b650e1be9ep-39,   0x1.da3b650e1f585p-39,         -0x1p+0, INEXACT) // 3.369621102881548856142759785627e-12
T(RZ,   0x1.f7fffffffeb54p-39,   0x1.f800000002957p-39,         -0x1p+0, INEXACT) // 3.581135388228767515012326356223e-12
T(RN,    0x1.d073a1cb8cf81p-4,    0x1.ebceec01f86dap-4,          0x1p-1, INEXACT) // 1.133915252801767220569573169087e-01
T(RZ,   0x1.07ffffffffd2ap-40,   0x1.08000000005abp-40,         -0x1p+0, INEXACT) // 9.379164112031856308174832768330e-13
T(RN,   0x1.6eeee8953b88dp-40,   0x1.6eeee8953c8fdp-40,          0x1p-1, INEXACT) // 1.303608728285667019096179834925e-12
T(RN,   0x1.6fb79fd6dfea8p-40,   0x1.6fb79fd6e0f29p-40,         -0x1p-1, INEXACT) // 1.306394220197366811490171403839e-12
T(RZ,   0x1.37ffffffffc0ap-40,   0x1.38000000007ebp-40,         -0x1p+0, INEXACT) // 1.108446667785551514289732966293e-12
T(RZ,   0x1.afffffffff868p-40,   0x1.b000000000f2fp-40,         -0x1p+0, INEXACT) // 1.534772309241423813808092508350e-12
T(RZ,   0x1.f4b82ffeb5da4p-40,   0x1.f4b82ffeb7c3ep-40,         -0x1p+0, INEXACT) // 1.778912954169010710960318613232e-12
T(RZ,     0x1.7fffffffffap-40,   0x1.8000000000bffp-40,         -0x1p+0, INEXACT) // 1.364242052659082164142851208372e-12
T(RZ,   0x1.a291a9605ce1dp-40,    0x1.a291a9605e38p-40, -0x1.4f56d2p-52, INEXACT) // 1.487055778884720977210065858348e-12
T(RZ,   0x1.f7ffffffff5aap-40,   0x1.f8000000014abp-40,         -0x1p+0, INEXACT) // 1.790567694114918112950698166204e-12
T(RZ,   0x1.460afe3e7cf76p-41,   0x1.460afe3e7d5f2p-41,         -0x1p+0, INEXACT) // 5.791686098835062017882607358871e-13
T(RN,   0x1.cc39dd320459dp-41,   0x1.cc39dd320528bp-41,          0x1p-1, INEXACT) // 8.175256585893962896652626242275e-13
T(RN,   0x1.94bb650391d3dp-41,   0x1.94bb65039273dp-41,          0x1p-1, INEXACT) // 7.189484742661675165154062653162e-13
T(RZ,   0x1.e93e8b71a4dd6p-41,   0x1.e93e8b71a5c72p-41, -0x1.0d1112p-51, INEXACT) // 8.690724855238409533128777904119e-13
T(RN,   0x1.1874eee5c5d0cp-42,   0x1.1874eee5c5f73p-42,          0x1p-1, INEXACT) // 2.490956510279911583289984916904e-13
T(RZ,   0x1.324e99e0fd993p-42,    0x1.324e99e0fdc7p-42, -0x1.7be63cp-51, INEXACT) // 2.720552987380497607108836680092e-13
T(RZ,    0x1.7fffffffffe8p-42,   0x1.80000000002ffp-42,         -0x1p+0, INEXACT) // 3.410605131648287021725329368514e-13
T(RN,    0x1.8d076a5427a2p-42,   0x1.8d076a5427eefp-42,         -0x1p-1, INEXACT) // 3.526325597726107824465563477484e-13
T(RZ,   0x1.dfffffffffda8p-42,   0x1.e0000000004afp-42,         -0x1p+0, INEXACT) // 4.263256414560298192639140736935e-13
T(RN,   0x1.15d1f1225f82ap-43,   0x1.15d1f1225f958p-43,          0x1p-1, INEXACT) // 1.233769023243168389018266999356e-13
T(RZ,    0x1.542a278d2d01p-45,    0x1.542a278d2d08p-45,         -0x1p+0, INEXACT) // 3.776586443654601935473502996355e-14
T(RN,   0x1.db2cfe686fe33p-45,    0x1.db2cfe686ff1p-45,          0x1p-1, INEXACT) // 5.275510661177437820176944937496e-14
T(RN,   0x1.1520cd1372fdep-46,   0x1.1520cd1373003p-46,         -0x1p-1, INEXACT) // 1.538370149106847187694267014300e-14
T(RN,   0x1.44c3b83e57142p-46,   0x1.44c3b83e57175p-46,         -0x1p-1, INEXACT) // 1.802805294398302203023757228049e-14
T(RZ,   0x1.36406304452f6p-46,   0x1.3640630445325p-46,   -0x1.584dp-51, INEXACT) // 1.722241853988860473407695988289e-14
T(RN,   0x1.ea8cfb6454784p-46,   0x1.ea8cfb64547f9p-46,         -0x1p-1, INEXACT) // 2.723103470137968084262979037428e-14
T(RN,      0x1.eeb53f23abp-46,   0x1.eeb53f23ab078p-46,          0x1p-1, INEXACT) // 2.746181030797642778648512859835e-14
T(RN,   0x1.3fffffffffffcp-48,   0x1.4000000000009p-48,          0x1p-1, INEXACT) // 4.440892098500623006250905788316e-15
T(RZ,   0x1.52a7fa9d2f8e5p-48,   0x1.52a7fa9d2f8f2p-48,         -0x1p+0, INEXACT) // 4.699798436761761336777438422103e-15
T(RN,   0x1.ad5336963eef4p-48,   0x1.ad5336963ef0ap-48,         -0x1p-1, INEXACT) // 5.958081967793449171579456825525e-15
T(RZ,   0x1.2c2fc595456a3p-48,   0x1.2c2fc595456adp-48,         -0x1p+0, INEXACT) // 4.165926057296532805856512679696e-15
T(RZ,   0x1.8a85c24f70653p-48,   0x1.8a85c24f70665p-48,         -0x1p+0, INEXACT) // 5.475099487534303475125669080825e-15
T(RZ,   0x1.e768d399dc466p-48,   0x1.e768d399dc483p-48, -0x1.3dc2e4p-51, INEXACT) // 6.764165321960913044133853660790e-15
T(RN,   0x1.ffffffffffffbp-49,   0x1.0000000000006p-48,          0x1p-1, INEXACT) // 3.552713678800498957203358285361e-15
T(RN,    0x1.6c30481c8c9e8p-5,    0x1.7467bb86605b2p-5,          0x1p-1, INEXACT) // 4.445661625176794418123904506501e-02
T(RZ,    0x1.7e6fd1401d233p-5,    0x1.878113fde1c06p-5,         -0x1p+0, INEXACT) // 4.668417805888615962350840504769e-02
T(RN,    0x1.be393873d8fa8p-5,    0x1.ca99aa8488d0ap-5,         -0x1p-1, INEXACT) // 5.447064424404796101342185465910e-02
T(RN,   0x1.7ffffffffffffp-50,   0x1.8000000000004p-50,          0x1p-1, INEXACT) // 1.332267629550187651293131696456e-15
T(RN,   0x1.94c583ada5b53p-51,   0x1.94c583ada5b56p-51,          0x1p-1, INEXACT) // 7.021666937153402449716262382570e-16
T(RN,   0x1.ffffffffffffdp-51,                 0x1p-50,         -0x1p-1, INEXACT) // 8.881784197001249365160658765932e-16
T(RN,    0x1.1dd3799f6bb5fp-6,    0x1.205575069701bp-6,          0x1p-1, INEXACT) // 1.744543912144124950258650130763e-02
T(RZ,    0x1.5768bb69502e1p-8,     0x1.584f777269a1p-8,  -0x1.b915ap-51, INEXACT) // 5.240007166606303924683007977592e-03
T(RZ,    0x1.926936f81c081p-8,     0x1.93a6243fe868p-8,         -0x1p+0, INEXACT) // 6.140304489335447236941778470509e-03
T(RN,    0x1.0af5b58ee4bf4p-9,    0x1.0b3b5a8b5d045p-9,         -0x1p-1, INEXACT) // 2.036741650451196275484200270967e-03
T(RZ,    0x1.8f329f8b78843p-9,    0x1.8fce67bb4f9c3p-9,         -0x1p+0, INEXACT) // 3.045637107548267077244963374483e-03
T(RZ,    0x1.b0aa923e5d392p-9,    0x1.b16195cfdda6bp-9,         -0x1p+0, INEXACT) // 3.300981857302828260947169525252e-03
T(RZ,    0x1.ee8ceec4781a3p-9,    0x1.ef7c14cbe1201p-9, -0x1.4ce54ep-51, INEXACT) // 3.773121019762197460994945785728e-03
T(RN,    0x1.80345fb9bf501p+0,    0x1.be1d656d0ed3cp+1,         -0x1p-1, INEXACT) // 1.500799162720170665252794606204e+00
T(RN,    0x1.a083788425ab6p+0,    0x1.05abe6a4c4281p+2,          0x1p-1, INEXACT) // 1.627006084692465659458093796275e+00
T(RN,    0x1.aca7ae8da5a7bp+0,    0x1.157d4acd7e557p+2,          0x1p-1, INEXACT) // 1.674433621961411544631914694037e+00
T(RZ,    0x1.53068b2bacac1p+1,    0x1.a44ff9a896f5dp+3,         -0x1p+0, INEXACT) // 2.648637195897521667831142622163e+00
T(RZ,    0x1.df801ca8a88cbp+1,    0x1.4ad7f797be69ap+5,         -0x1p+0, INEXACT) // 3.746097166397793554182271691388e+00
T(RZ,    0x1.333a83013057ep+2,    0x1.e242354c34a34p+6, -0x1.3df4a4p-53, INEXACT) // 4.800446273003556640901479113381e+00
T(RN,    0x1.aa1b465630fa4p+2,    0x1.84f6653f47e5ep+9,          0x1p-1, INEXACT) // 6.657914718791207775439033866860e+00
T(RN,    0x1.60bb5fb993b99p+3,   0x1.de94d34fcccfep+15,          0x1p-1, INEXACT) // 1.102287279363172167734319373267e+01
T(RN,    0x1.6d2883e37b4d7p+3,   0x1.60d65c9585ca5p+16,          0x1p-1, INEXACT) // 1.141119570188531717747082439018e+01
T(RN,    0x1.796c771af1e4bp+3,   0x1.02d399f8e15f2p+17,          0x1p-1, INEXACT) // 1.179449038756060552657345397165e+01
T(RZ,    0x1.08f51434652c3p+4,   0x1.daac439b157e5p+23,  -0x1.c6823p-55, INEXACT) // 1.655983372179867885165549523663e+01
T(RZ,    0x1.0ae38aa7bf73ep+5,   0x1.181ea60203d29p+48, -0x1.aa817ap-51, INEXACT) // 3.336110430768029289083642652258e+01
T(RN,   -0x1.1ab099b07ee77p-1,   -0x1.b275aa376de93p-2,         -0x1p-1, INEXACT) // -5.521286037396312407210530182056e-01
T(RN,   -0x1.22c36ae45e85fp-1,   -0x1.bbaed410a34b4p-2,          0x1p-1, INEXACT) // -5.678971675654443940217674935411e-01
T(RN,   -0x1.2cd0c35ecc0b9p-1,   -0x1.c6f71835c6056p-2,         -0x1p-1, INEXACT) // -5.875302365511948510246043042571e-01
T(RN,   -0x1.80392a196b902p-1,   -0x1.0e40f7c7610a8p-1,         -0x1p-1, INEXACT) // -7.504361301451185628508255831548e-01
T(RZ,  -0x1.0f1f661a97dabp-10,  -0x1.0efb84d590daap-10,  0x1.57b048p-51, INEXACT) // -1.034250838209386678598344921909e-03
T(RN,  -0x1.05f634cf839a4p-10,  -0x1.05d4b5ac409bep-10,          0x1p-1, INEXACT) // -9.993047459634163756647673437783e-04
T(RN,  -0x1.89a8c886e52f4p-10,  -0x1.895d27435f0e8p-10,         -0x1p-1, INEXACT) // -1.501691092675003398604349769130e-03
T(RN,  -0x1.a168287b8f008p-10,  -0x1.a1132179c08b9p-10,         -0x1p-1, INEXACT) // -1.592280836930195023204426263419e-03
T(RZ,  -0x1.91ad2e5ca3434p-11,  -0x1.9185ccefbfa54p-11,          0x1p+0, INEXACT) // -7.661371015089736037639855936732e-04
T(RN,   -0x1.0fcec2f150b9p-12,  -0x1.0fc5be6923a5cp-12,         -0x1p-1, INEXACT) // -2.592159863363191832363874311795e-04
T(RN,  -0x1.27613c160f4bdp-12,  -0x1.275695cdad3f6p-12,          0x1p-1, INEXACT) // -2.816961508676598985485839410359e-04
T(RN,  -0x1.2b94f4ceb8146p-12,  -0x1.2b8a0068c3577p-12,         -0x1p-1, INEXACT) // -2.857035259875749999211591578785e-04
T(RN,  -0x1.6d56dad4dbc5fp-12,  -0x1.6d46904a8fd22p-12,         -0x1p-1, INEXACT) // -3.484146848710730089669629361282e-04
T(RN,  -0x1.41273994c4678p-12,  -0x1.411aa2cddc42cp-12,          0x1p-1, INEXACT) // -3.062755798036507874637646153815e-04
T(RZ,  -0x1.4ef3ddbb27828p-12,  -0x1.4ee62c10c03a8p-12,          0x1p+0, INEXACT) // -3.194356938339714714614192558884e-04
T(RN,  -0x1.64e818f700ef9p-12,  -0x1.64d88cb7de3c1p-12,          0x1p-1, INEXACT) // -3.403726872763658908328798791132e-04
T(RZ,  -0x1.8503555f8030ep-12,  -0x1.84f0dcdc27564p-12,  0x1.4a3778p-51, INEXACT) // -3.709917272943099404367006677319e-04
T(RN,  -0x1.f4ae809dd0631p-12,  -0x1.f48fe80c0d45ap-12,         -0x1p-1, INEXACT) // -4.774872303308945659973405728493e-04
T(RZ,  -0x1.cead59cec620dp-13,  -0x1.cea0493527c42p-13,  0x1.b438c8p-54, INEXACT) // -2.206216581377571565956291488320e-04
T(RN,  -0x1.3fff180603bc4p-14,    -0x1.3ffbf80fc0ep-14,          0x1p-1, INEXACT) // -7.629310138688923667929508987129e-05
T(RN,  -0x1.fdb28a850de72p-14,  -0x1.fdaa9cfb2b049p-14,         -0x1p-1, INEXACT) // -1.215213361128676856654645677125e-04
T(RN,  -0x1.f5c9d0a8c2db9p-15,   -0x1.f5c5f91e3e4bp-15,         -0x1p-1, INEXACT) // -5.981783153260638213931724149752e-05
T(RZ,  -0x1.9201cf8d7e0dap-15,   -0x1.91ff58466314p-15,          0x1p+0, INEXACT) // -4.792297759687184140631882600658e-05
T(RZ,  -0x1.c227eee00f734p-15,  -0x1.c224d75345593p-15,          0x1p+0, INEXACT) // -5.366277559957916541179268055117e-05
T(RN,  -0x1.d502542073e7dp-16,  -0x1.d500a680b623bp-16,         -0x1p-1, INEXACT) // -2.795512057379580969054995442935e-05
T(RZ,  -0x1.7c47f56857315p-16,  -0x1.7c46daf608a87p-16,          0x1p+0, INEXACT) // -2.266651918724205998158412189714e-05
T(RN,   -0x1.242015a4dce9p-17,  -0x1.241fc24e9f691p-17,          0x1p-1, INEXACT) // -8.706013270055255577964392621482e-06
T(RN,  -0x1.2601670e72e61p-17,  -0x1.260112a4b4e09p-17,          0x1p-1, INEXACT) // -8.762046061947655628825322449149e-06
T(RZ,  -0x1.3907c6e050d84p-17,  -0x1.3907672f63356p-17,  0x1.9cb5c6p-51, INEXACT) // -9.329032253041801882060407580255e-06
T(RN,  -0x1.6c2d1aa96dccap-17,  -0x1.6c2c99257990bp-17,         -0x1p-1, INEXACT) // -1.085329616300062053062432110284e-05
T(RZ,   -0x1.7e94e5125807p-17,  -0x1.7e9456224f121p-17,          0x1p+0, INEXACT) // -1.140182078945858423595083319668e-05
T(RZ,  -0x1.8b0f67b46c1dcp-17,  -0x1.8b0ecf4a70943p-17,  0x1.eb167cp-51, INEXACT) // -1.177371073243863177455389990023e-05
T(RN,  -0x1.e4df1156e57ecp-17,  -0x1.e4de2bc01efc5p-17,          0x1p-1, INEXACT) // -1.445029253747603324156342785578e-05
T(RZ,  -0x1.f0bdc4310c393p-17,  -0x1.f0bcd33960ecap-17,  0x1.646968p-54, INEXACT) // -1.480404361772924135465159117819e-05
T(RN,  -0x1.3f4f5a5e1d5bap-17,  -0x1.3f4ef6cc7b1aap-17,          0x1p-1, INEXACT) // -9.516178746541966647050705963018e-06
T(RN,  -0x1.555b5316cb345p-17,  -0x1.555ae14bc982ap-17,         -0x1p-1, INEXACT) // -1.017322351301034006958948913146e-05
T(RZ,  -0x1.14eddeb406831p-18,  -0x1.14edb941d13bep-18,          0x1p+0, INEXACT) // -4.126566341989101753854555371115e-06
T(RN,  -0x1.998a1d6af0065p-18,  -0x1.9989cb85a760ep-18,         -0x1p-1, INEXACT) // -6.102614274306003069186805226609e-06
T(RN,  -0x1.ab79422f4afadp-18,  -0x1.ab78e8f59fde2p-18,         -0x1p-1, INEXACT) // -6.369854005410581971908124537807e-06
T(RN,  -0x1.6fddc52af837dp-18,  -0x1.6fdd83174cb38p-18,          0x1p-1, INEXACT) // -5.481634881982701329374441795439e-06
T(RZ,  -0x1.db3c2d03b8371p-18,  -0x1.db3bbebcbda03p-18,          0x1p+0, INEXACT) // -7.081554261851499442912642040548e-06
T(RN,  -0x1.8e53bbf839b9fp-18,  -0x1.8e536e7f34ca3p-18,         -0x1p-1, INEXACT) // -5.935536130353019351605422387896e-06
T(RN,  -0x1.2bdc15fbc0542p-19,  -0x1.2bdc000803dd7p-19,         -0x1p-1, INEXACT) // -2.234128940404326811033312166765e-06
T(RN,  -0x1.1216bde35b358p-19,  -0x1.1216ab8c10fefp-19,          0x1p-1, INEXACT) // -2.042120955605979435538641086900e-06
T(RZ,  -0x1.42d8d1f14a75ap-19,  -0x1.42d8b87ee94f9p-19,  0x1.ea831ap-51, INEXACT) // -2.405397247291877123071424798839e-06
T(RN,   -0x1.1570e1f7cffb3p-2,   -0x1.e610b3cac1306p-3,         -0x1p-1, INEXACT) // -2.709384257796003114826532964798e-01
T(RZ,   -0x1.add1dce7cd5bcp-2,   -0x1.5f0357a4cf6c5p-2,          0x1p+0, INEXACT) // -4.197458759766410363312161280192e-01
T(RZ,   -0x1.f31bfe026a32ep-2,     -0x1.8b0b6b63cddp-2,          0x1p+0, INEXACT) // -4.874114693616772298057071566291e-01
T(RN,  -0x1.0498e25388035p-20,  -0x1.0498da0950f82p-20,         -0x1p-1, INEXACT) // -9.708002338751465886665424978585e-07
T(RN,  -0x1.3f20a8b5e3b57p-20,  -0x1.3f209c4750c32p-20,         -0x1p-1, INEXACT) // -1.188842856578606281057314784932e-06
T(RN,  -0x1.64d77da92bd2cp-20,  -0x1.64d76e1debef3p-20,          0x1p-1, INEXACT) // -1.329339151017446716228614239652e-06
T(RZ,  -0x1.d008d16c9c776p-20,  -0x1.d008b7239db9bp-20,          0x1p+0, INEXACT) // -1.728663018199227189951447045124e-06
T(RZ,  -0x1.ea695a973fd94p-20,  -0x1.ea693d3b8533fp-20,          0x1p+0, INEXACT) // -1.826925346837129087590196468982e-06
T(RZ,  -0x1.0f48d4b19f122p-21,  -0x1.0f48d033b202bp-21,  0x1.1af07ep-51, INEXACT) // -5.053067495121433067630520655222e-07
T(RN,   -0x1.34b5c03fe14dp-21,  -0x1.34b5ba6eca012p-21,          0x1p-1, INEXACT) // -5.750171183516262970189872327786e-07
T(RZ,  -0x1.c8299e237262ep-21,  -0x1.c82991702176ap-21,          0x1p+0, INEXACT) // -8.496689968769756365639172698834e-07
T(RN,   -0x1.0f9b1c5ad2f3p-22,  -0x1.0f9b1a1a7f6e3p-22,         -0x1p-1, INEXACT) // -2.529527073815718499617648251654e-07
T(RZ,  -0x1.8607ff42afa59p-22,  -0x1.8607fa9e36f2fp-22,          0x1p+0, INEXACT) // -3.632448974214619337876985925156e-07
T(RN,  -0x1.b975fa8d78b3ep-22,  -0x1.b975f49ae9626p-22,         -0x1p-1, INEXACT) // -4.111424594927800921052916775789e-07
T(RN,  -0x1.8a8597b7c4b28p-23,  -0x1.8a859557c5383p-23,          0x1p-1, INEXACT) // -1.837135508100481621720405714382e-07
T(RZ,  -0x1.3cc6c05cdacaap-23,  -0x1.3cc6bed4df86ap-23,          0x1p+0, INEXACT) // -1.475104935104347234668339689662e-07
T(RN,  -0x1.a6575a3a33c26p-23,  -0x1.a65757816faa1p-23,          0x1p-1, INEXACT) // -1.966679564258717782011538343506e-07
T(RN,  -0x1.a75c69c705603p-23,  -0x1.a75c670ae2dc4p-23,          0x1p-1, INEXACT) // -1.971428231501148585428625841995e-07
T(RN,  -0x1.b1ec040e36b4dp-24,  -0x1.b1ec029e7695fp-24,          0x1p-1, INEXACT) // -1.010303238598533392938650277322e-07
T(RZ,  -0x1.3467f1e7ea86ep-25,  -0x1.3467f18b07f4ep-25,  0x1.49c9c8p-54, INEXACT) // -3.590318781107687907388218350943e-08
T(RZ,  -0x1.759aa77e83f31p-25,  -0x1.759aa6f634f0cp-25,          0x1p+0, INEXACT) // -4.349324366295251035758123660420e-08
T(RN,  -0x1.b2d4689ccd32ep-25,  -0x1.b2d467e427fa5p-25,          0x1p-1, INEXACT) // -5.062084194041830923558835308648e-08
T(RZ,  -0x1.cdd26d66681f8p-25,  -0x1.cdd26c96203cfp-25,          0x1p+0, INEXACT) // -5.376315463938804059440177383900e-08
T(RZ,  -0x1.d5c2570fb5b71p-25,  -0x1.d5c25638354dap-25,          0x1p+0, INEXACT) // -5.468716157495823572460248653167e-08
T(RN,  -0x1.0a674f3b47648p-26,  -0x1.0a674f18a0094p-26,         -0x1p-1, INEXACT) // -1.550672766331305955332935542917e-08
T(RZ,  -0x1.4c681ec7966ffp-26,  -0x1.4c681e91a2a8ap-26,          0x1p+0, INEXACT) // -1.934861762332861477124938546276e-08
T(RZ,  -0x1.773601f556083p-27,  -0x1.773601d2f713ep-27,  0x1.fdf45ap-51, INEXACT) // -1.092007638019154297399819709058e-08
T(RZ,  -0x1.baf8787c68b3ap-27,  -0x1.baf8784c80c49p-27,  0x1.125c52p-51, INEXACT) // -1.289214090415163684736023143752e-08
T(RZ,  -0x1.eead8307edfc3p-27,  -0x1.eead82cc2fda8p-27,  0x1.c164a4p-53, INEXACT) // -1.439701825799449366368367445512e-08
T(RZ,  -0x1.fd502c508a1cdp-27,  -0x1.fd502c11359e3p-27,          0x1p+0, INEXACT) // -1.482296432913418293673250711534e-08
T(RN,  -0x1.066c67246ca9cp-28,  -0x1.066c671c04994p-28,         -0x1p-1, INEXACT) // -3.818763781256577140510582459541e-09
T(RZ,  -0x1.be4c1b674fc4bp-28,  -0x1.be4c1b4eff5a7p-28,          0x1p+0, INEXACT) // -6.494480376497894852262762120610e-09
T(RN,  -0x1.4d4b7ec11a5fbp-29,  -0x1.4d4b7eba52a9cp-29,         -0x1p-1, INEXACT) // -2.425039586285558039232762038754e-09
T(RZ,   -0x1.290ea09e36479p-3,    -0x1.1484b3cd038fp-3,   0x1.09becp-56, INEXACT) // -1.450474308283309643474723316103e-01
T(RZ,   -0x1.343d5853ab1bap-3,   -0x1.1e2a26c6cbcffp-3,  0x1.43c9b8p-54, INEXACT) // -1.505076313527647369205908489675e-01
T(RZ,   -0x1.3b89bb1b787cdp-3,   -0x1.246e9c005c036p-3,  0x1.4c6ed2p-52, INEXACT) // -1.540712945707682079987677070676e-01
T(RZ,   -0x1.b8144d498cc5bp-3,   -0x1.8c024d0aa27b2p-3,          0x1p+0, INEXACT) // -2.148824728079457846430244671865e-01
T(RZ,   -0x1.cddf723d3e52fp-3,   -0x1.9d7ec7df33dbcp-3,  0x1.4c5198p-51, INEXACT) // -2.255238461437243102647443038222e-01
T(RZ,   -0x1.f193dbe5f18bbp-3,   -0x1.b9be811308061p-3,          0x1p+0, INEXACT) // -2.429577998684119000127878962303e-01
T(RN,  -0x1.64808871369c2p-30,  -0x1.6480886d55b0bp-30,         -0x1p-1, INEXACT) // -1.296947018793988569947992376481e-09
T(RN,  -0x1.649d68b5eeff4p-30,  -0x1.649d68b20d72fp-30,         -0x1p-1, INEXACT) // -1.297357372125221613015861791109e-09
T(RN,  -0x1.e09ccbbbb4315p-30,  -0x1.e09ccbb4a7989p-30,          0x1p-1, INEXACT) // -1.748458030205084017555144185196e-09
T(RZ,  -0x1.1d39b081ba323p-31,  -0x1.1d39b0807c68ap-31,          0x1p+0, INEXACT) // -5.188218884163258208179388108192e-10
T(RZ,  -0x1.89756d7b7e585p-31,  -0x1.89756d79219e9p-31,  0x1.2c1418p-51, INEXACT) // -7.156972093412989137946802110804e-10
T(RZ,  -0x1.0f4e4d7c4341fp-32,  -0x1.0f4e4d7bb37e8p-32,  0x1.72fe5cp-51, INEXACT) // -2.467512511733670067589127189352e-10
T(RN,  -0x1.c1711a3ce6b76p-32,  -0x1.c1711a3b5c306p-32,          0x1p-1, INEXACT) // -4.087649418656948347732078449226e-10
T(RN,  -0x1.e84210839e30fp-32,   -0x1.e8421081cc93p-32,         -0x1p-1, INEXACT) // -4.440681227476172495430103381685e-10
T(RZ,  -0x1.3fa8a7478f956p-33,  -0x1.3fa8a7472bcbfp-33,   0x1.33ae6p-51, INEXACT) // -1.453639936167445986785947130052e-10
T(RZ,   -0x1.9b99a8ba1b4ep-33,  -0x1.9b99a8b975dc5p-33,  0x1.dd26f6p-52, INEXACT) // -1.871741145893719459254721270477e-10
T(RZ,  -0x1.020000000ad58p-34,   -0x1.01ffffffea55p-34,   0x1.d5802p-56, INEXACT) // -5.866240826492741770274897509531e-11
T(RZ,    -0x1.200000000d8p-34,     -0x1.1fffffffe5p-34,   0x1.6c7ffp-55, INEXACT) // -6.548361852836551717912862841109e-11
T(RZ,  -0x1.110000000c216p-34,  -0x1.10ffffffe7bd4p-34,   0x1.264abp-55, INEXACT) // -6.207301339664452873637813059459e-11
T(RZ,  -0x1.4d000000120c6p-34,  -0x1.4cffffffdbe74p-34,  0x1.45be18p-54, INEXACT) // -7.571543392355174696210817576395e-11
T(RN,  -0x1.679d5e93ff863p-34,  -0x1.679d5e93c060dp-34,          0x1p-1, INEXACT) // -8.176692162977554151767726243157e-11
T(RN,  -0x1.5bbf5535d63bfp-34,  -0x1.5bbf55359b2fep-34,          0x1p-1, INEXACT) // -7.906860308958056434137659845696e-11
T(RZ,  -0x1.6b00000015726p-34,  -0x1.6affffffd51b4p-34,  0x1.cbf6d8p-54, INEXACT) // -8.253664418702862052970125225198e-11
T(RZ,  -0x1.3e00000010758p-34,   -0x1.3dffffffdf15p-34,  0x1.0ee5e8p-54, INEXACT) // -7.230482879181912629199365099577e-11
T(RZ,  -0x1.2f0000000ef16p-34,  -0x1.2effffffe21d4p-34,   0x1.be942p-55, INEXACT) // -6.889422366009038303100046854482e-11
T(RZ,  -0x1.2f8050f9b0af3p-34,  -0x1.2f8050f983b51p-34,  0x1.16fd14p-53, INEXACT) // -6.900819143670993854775895773700e-11
T(RZ,   -0x1.5c00000013b6p-34,   -0x1.5bffffffd894p-34,   0x1.84856p-54, INEXACT) // -7.912603905528824504134404284935e-11
T(RZ,  -0x1.e300000025f86p-34,  -0x1.e2ffffffb40f4p-34,  0x1.686f2ep-52, INEXACT) // -1.098214852410912111649272508932e-10
T(RZ,  -0x1.b2b72609bbd6ep-34,  -0x1.b2b726095f90bp-34,  0x1.b95e9cp-52, INEXACT) // -9.884284376406888805282340025783e-11
T(RZ,   -0x1.980000001b18p-34,    -0x1.97ffffffc9dp-34,  0x1.6f091cp-53, INEXACT) // -9.276845958227301144950093436323e-11
T(RZ,  -0x1.7a00000017418p-34,   -0x1.79ffffffd17dp-34,   0x1.0e6aep-53, INEXACT) // -8.594724931877287342717980397184e-11
T(RZ,  -0x1.8900000019236p-34,  -0x1.88ffffffcdb94p-34,   0x1.3bf6dp-53, INEXACT) // -8.935785445052100373377969800892e-11
T(RZ,  -0x1.c500000021666p-34,  -0x1.c4ffffffbd334p-34,  0x1.16e36cp-52, INEXACT) // -1.030002749775522990513926973295e-10
T(RZ,  -0x1.b60000001f398p-34,   -0x1.b5ffffffc18dp-34,  0x1.e77cf4p-53, INEXACT) // -9.958966984578865910830743402352e-11
T(RZ,  -0x1.a70000001d1f6p-34,  -0x1.a6ffffffc5c14p-34,  0x1.a80fccp-53, INEXACT) // -9.617906471402889657434351303476e-11
T(RZ,   -0x1.d400000023a6p-34,   -0x1.d3ffffffb8b4p-34,  0x1.3db3e8p-52, INEXACT) // -1.064108801093198164035993029527e-10
T(RZ,  -0x1.f2000000285d8p-34,   -0x1.f1ffffffaf45p-34,  0x1.975688p-52, INEXACT) // -1.132320903728664833353765411508e-10
T(RZ,  -0x1.0b00000005cd3p-35,  -0x1.0afffffff465ap-35,   0x1.0d428p-58, INEXACT) // -3.035438567182504472866519118467e-11
T(RZ,  -0x1.0e00000005eecp-35,  -0x1.0dfffffff4228p-35,    0x1.1991p-58, INEXACT) // -3.069544618499336309904693220703e-11
T(RZ,  -0x1.1d000000069c3p-35,  -0x1.1cfffffff2c7ap-35,    0x1.5d8cp-58, INEXACT) // -3.240074875083553656232383866638e-11
T(RZ,  -0x1.1a0000000678cp-35,  -0x1.19fffffff30e8p-35,   0x1.4f0f8p-58, INEXACT) // -3.205968823766702432148603052817e-11
T(RZ,  -0x1.29000000072dbp-35,  -0x1.28fffffff1a4ap-35,    0x1.9c3ep-58, INEXACT) // -3.376499080350997326658720545097e-11
T(RN,  -0x1.24904c909613ap-35,  -0x1.24904c90812e1p-35,         -0x1p-1, INEXACT) // -3.326063827966891529261519486370e-11
T(RZ,   -0x1.2c0000000753p-35,   -0x1.2bfffffff15ap-35,    0x1.ad27p-58, INEXACT) // -3.410605131667867937788108070505e-11
T(RZ,   -0x1.3800000007ecp-35,   -0x1.37fffffff028p-35,    0x1.f60cp-58, INEXACT) // -3.547029336935389156396871595308e-11
T(RN,  -0x1.454bc7e752cddp-35,  -0x1.454bc7e738f84p-35,         -0x1p-1, INEXACT) // -3.698187572774437271313676380524e-11
T(RZ,  -0x1.4700000008b3bp-35,  -0x1.46ffffffee98ap-35,   0x1.2ee44p-57, INEXACT) // -3.717559593519877921363056203450e-11
T(RZ,  -0x1.560000000984cp-35,  -0x1.55ffffffecf68p-35,   0x1.6a694p-57, INEXACT) // -3.888089850104463621557274369522e-11
T(RZ,  -0x1.830000000c303p-35,  -0x1.82ffffffe79fap-35,   0x1.291b2p-56, INEXACT) // -4.399680619858802333508130215322e-11
T(RZ,   -0x1.680000000a8cp-35,   -0x1.67ffffffeae8p-35,    0x1.bcf2p-57, INEXACT) // -4.092726158006094416291340465277e-11
T(RZ,  -0x1.770000000b71bp-35,  -0x1.76ffffffe91cap-35,   0x1.05ef2p-56, INEXACT) // -4.263256414590893373987232458797e-11
T(RZ,   -0x1.a40000000e5bp-35,   -0x1.a3ffffffe34ap-35,   0x1.9c28ap-56, INEXACT) // -4.774847184345871858443109786939e-11
T(RZ,  -0x1.860000000c60cp-35,  -0x1.85ffffffe73e8p-35,   0x1.326d2p-56, INEXACT) // -4.433786671175789266911158010247e-11
T(RZ,  -0x1.ce000000115ecp-35,  -0x1.cdffffffdd428p-35,   0x1.2db89p-55, INEXACT) // -5.252331902784638891320227783603e-11
T(RZ,  -0x1.b30000000f663p-35,  -0x1.b2ffffffe133ap-35,   0x1.da44cp-56, INEXACT) // -4.945377440931058557051136012182e-11
T(RZ,  -0x1.5900000009afbp-35,  -0x1.58ffffffeca0ap-35,   0x1.774bcp-57, INEXACT) // -3.922195901421392393823482029688e-11
T(RZ,  -0x1.650000000a5f3p-35,  -0x1.64ffffffeb41ap-35,   0x1.ae4c8p-57, INEXACT) // -4.058620106689146256979526093525e-11
T(RZ,   -0x1.740000000b43p-35,   -0x1.73ffffffe97ap-35,    0x1.fb4ep-57, INEXACT) // -4.229150363273925827629811375458e-11
T(RZ,  -0x1.950000000d593p-35,  -0x1.94ffffffe54dap-35,   0x1.645bep-56, INEXACT) // -4.604316927760782095063117119628e-11
T(RZ,  -0x1.a10000000e26bp-35,  -0x1.a0ffffffe3b2ap-35,   0x1.90822p-56, INEXACT) // -4.740741133028846150948868568843e-11
T(RZ,  -0x1.bf0000001042bp-35,  -0x1.beffffffdf7aap-35,   0x1.08675p-55, INEXACT) // -5.081801646199277709301741154086e-11
T(RZ,  -0x1.d10000001198bp-35,  -0x1.d0ffffffdcceap-35,   0x1.35a27p-55, INEXACT) // -5.286437954101722759951289136458e-11
T(RZ,  -0x1.c2000000107acp-35,  -0x1.c1ffffffdf0a8p-35,   0x1.0f92dp-55, INEXACT) // -5.115907697516342190887195795355e-11
T(RZ,  -0x1.3b00000008133p-35,  -0x1.3affffffefd9ap-35,   0x1.04d1cp-57, INEXACT) // -3.581135388252279154571865832302e-11
T(RZ,  -0x1.4a00000008dccp-35,  -0x1.49ffffffee468p-35,   0x1.3a294p-57, INEXACT) // -3.751665644836787306583657152030e-11
T(RZ,  -0x1.920000000d26cp-35,  -0x1.91ffffffe5b28p-35,   0x1.59eaap-56, INEXACT) // -4.570210876443775774614482613117e-11
T(RZ,    -0x1.b00000000f3p-35,    -0x1.afffffffe1ap-35,   0x1.cd51ep-56, INEXACT) // -4.911271389614013462511288082499e-11
T(RZ,  -0x1.dd00000012843p-35,  -0x1.dcffffffdaf7ap-35,    0x1.56dbp-55, INEXACT) // -5.422862159370097008566747971051e-11
T(RZ,  -0x1.ef00000013f0bp-35,  -0x1.eeffffffd81eap-35,   0x1.8d9c6p-55, INEXACT) // -5.627498467272774703763576492457e-11
T(RZ,    -0x1.e000000012cp-35,    -0x1.dfffffffda8p-35,   0x1.5f8ffp-55, INEXACT) // -5.456968210687200264243416035492e-11
T(RZ,  -0x1.fe000000152acp-35,  -0x1.fdffffffd5aa8p-35,   0x1.c00aap-55, INEXACT) // -5.798028723858446078511770507353e-11
T(RZ,  -0x1.fb00000014eb3p-35,  -0x1.faffffffd629ap-35,   0x1.b5979p-55, INEXACT) // -5.763922672541304048743889019739e-11
T(RN,  -0x1.fc0dbb4780477p-35,   -0x1.fc0dbb474143p-35,          0x1p-1, INEXACT) // -5.775901160010923387837778944470e-11
T(RZ,   -0x1.ec00000013b3p-35,   -0x1.ebffffffd89ap-35,   0x1.840f2p-55, INEXACT) // -5.593392415955652061041301716430e-11
T(RZ,  -0x1.1a000000033c6p-36,  -0x1.19fffffff9874p-36,    0x1.4f0cp-61, INEXACT) // -1.602984411879068617699778937032e-11
T(RZ,   -0x1.3800000003f6p-36,   -0x1.37fffffff814p-36,    0x1.f60cp-61, INEXACT) // -1.773514668462452321066380984764e-11
T(RZ,   -0x1.b00000000798p-36,    -0x1.affffffff0dp-36,    0x1.cd51p-59, INEXACT) // -2.455635694796956486813124755000e-11
T(RZ,  -0x1.ce00000008af6p-36,  -0x1.cdffffffeea14p-36,   0x1.2db88p-58, INEXACT) // -2.626165951380824866319894592385e-11
T(RZ,  -0x1.4148f0891d45dp-36,  -0x1.4148f08910ac1p-36,  0x1.67421cp-51, INEXACT) // -1.826293329725256836544220770923e-11
T(RZ,  -0x1.5600000004c26p-36,  -0x1.55fffffff67b4p-36,    0x1.6a68p-60, INEXACT) // -1.944044925045932959661016590427e-11
T(RZ,  -0x1.7400000005a18p-36,   -0x1.73fffffff4bdp-36,    0x1.fb4ep-60, INEXACT) // -2.114575181629510533483685754021e-11
T(RZ,  -0x1.9200000006936p-36,  -0x1.91fffffff2d94p-36,    0x1.59eap-59, INEXACT) // -2.285105438213185042534388475545e-11
T(RZ,  -0x1.a128341607db4p-36,  -0x1.a1283415f29d1p-36,          0x1p+0, INEXACT) // -2.371263262660719739628430897474e-11
T(RZ,  -0x1.ad8bd87f7c9dep-36,  -0x1.ad8bd87f6617fp-36,  0x1.ee180cp-51, INEXACT) // -2.441687867344864871277716304291e-11
T(RZ,  -0x1.ec00000009d98p-36,   -0x1.ebffffffec4dp-36,    0x1.840fp-58, INEXACT) // -2.796696207964790181054697987701e-11
T(RZ,   -0x1.08000000016bp-37,   -0x1.07fffffffd2ap-37,     0x1.014p-64, INEXACT) // -7.503331289636041292872720673312e-12
T(RN,  -0x1.1aa7bf951b169p-37,  -0x1.1aa7bf9516364p-37,         -0x1p-1, INEXACT) // -8.033545869526220624438404816881e-12
T(RZ,  -0x1.153e5af20fa1fp-37,  -0x1.153e5af20af0fp-37,  0x1.8a6d16p-51, INEXACT) // -7.879736336320189639013950909433e-12
T(RZ,  -0x1.2600000001c23p-37,  -0x1.25fffffffc7bap-37,     0x1.8bcp-64, INEXACT) // -8.355982572550415259969850016293e-12
T(RZ,  -0x1.440000000222cp-37,  -0x1.43fffffffbba8p-37,     0x1.23ep-63, INEXACT) // -9.208633855465031565137063254101e-12
T(RN,   -0x1.4ad1f828aed8p-37,  -0x1.4ad1f828a829fp-37,          0x1p-1, INEXACT) // -9.402475395023153449386122358904e-12
T(RZ,  -0x1.62000000028cbp-37,  -0x1.61fffffffae6ap-37,       0x1.ap-63, INEXACT) // -1.006128513837989020837436038674e-11
T(RN,  -0x1.9c0bce1f479a2p-37,  -0x1.9c0bce1f3d3d5p-37,         -0x1p-1, INEXACT) // -1.171105492190241689648487611115e-11
T(RZ,  -0x1.9e000000037cbp-37,  -0x1.9dfffffff906ap-37,    0x1.8518p-62, INEXACT) // -1.176658770421033450905920633648e-11
T(RN,  -0x1.a3c26ba35ab44p-37,  -0x1.a3c26ba34ff33p-37,         -0x1p-1, INEXACT) // -1.193028125860295973090827351133e-11
T(RN,  -0x1.889aa805b318ap-37,  -0x1.889aa805a9b04p-37,         -0x1p-1, INEXACT) // -1.115848039933907800212941046232e-11
T(RZ,  -0x1.bc0000000402cp-37,  -0x1.bbfffffff7fa8p-37,     0x1.016p-61, INEXACT) // -1.261923898712592016650675515360e-11
T(RZ,     -0x1.8000000003p-37,     -0x1.7ffffffffap-37,    0x1.1ff8p-62, INEXACT) // -1.091393642129499118968174141420e-11
T(RN,  -0x1.afe1c60dc0dcdp-37,  -0x1.afe1c60db57a6p-37,          0x1p-1, INEXACT) // -1.227482267466936799736618946970e-11
T(RZ,  -0x1.ded1c2faad6cfp-37,  -0x1.ded1c2fa9f6e9p-37,          0x1p+0, INEXACT) // -1.360886532770047376399276357036e-11
T(RZ,  -0x1.da00000004923p-37,  -0x1.d9fffffff6dbap-37,    0x1.4e4cp-61, INEXACT) // -1.347189027004174816202438786554e-11
T(RN,  -0x1.db3ec56b35986p-37,  -0x1.db3ec56b27cf6p-37,         -0x1p-1, INEXACT) // -1.350728097894548545342657391962e-11
T(RZ,   -0x1.f8000000052bp-37,   -0x1.f7fffffff5aap-37,     0x1.ab5p-61, INEXACT) // -1.432454155295781849561210447231e-11
T(RZ,  -0x1.1b59f383854d7p-38,  -0x1.1b59f38382da2p-38,          0x1p+0, INEXACT) // -4.026665180489708826571942904237e-12
T(RN,  -0x1.03f236c5e2208p-38,  -0x1.03f236c5e0109p-38,          0x1p-1, INEXACT) // -3.694056946832428135899352828638e-12
T(RZ,  -0x1.4400000001116p-38,  -0x1.43fffffffddd4p-38,     0x1.238p-66, INEXACT) // -4.604316927728982493506708440478e-12
T(RZ,  -0x1.4148f0891a1f6p-38,  -0x1.4148f08916f8fp-38,  0x1.66bdccp-53, INEXACT) // -4.565733324302719130966243610814e-12
T(RZ,  -0x1.0800000000b58p-38,   -0x1.07fffffffe95p-38,      0x1.01p-67, INEXACT) // -3.751665644815674813917948234734e-12
T(RZ,  -0x1.3800000000fd8p-38,   -0x1.37fffffffe05p-38,      0x1.f6p-67, INEXACT) // -4.433786671146301570543349687743e-12
T(RZ,  -0x1.ec00000002766p-38,  -0x1.ebfffffffb134p-38,      0x1.84p-64, INEXACT) // -6.991740519887533234888083337040e-12
T(RZ,  -0x1.7400000001686p-38,  -0x1.73fffffffd2f4p-38,      0x1.fbp-66, INEXACT) // -5.286437954059803120588177009349e-12
T(RZ,  -0x1.bc00000002016p-38,  -0x1.bbfffffffbfd4p-38,     0x1.016p-64, INEXACT) // -6.309619493556324866894480536447e-12
T(RZ,  -0x1.f800000002958p-38,   -0x1.f7fffffffad5p-38,     0x1.ab4p-64, INEXACT) // -7.162270776470359560693492426671e-12
T(RZ,    -0x1.80000000018p-38,     -0x1.7ffffffffdp-38,     0x1.1fcp-65, INEXACT) // -5.456968210642532511165552541049e-12
T(RZ,   -0x1.b000000001e6p-38,   -0x1.affffffffc34p-38,     0x1.cd4p-65, INEXACT) // -6.139089236973547008703088225781e-12
T(RZ,  -0x1.84a8c38b78b67p-39,  -0x1.84a8c38b76685p-39,          0x1p+0, INEXACT) // -2.761589952463470001883762912088e-12
T(RZ,    -0x1.089bbf535475p-4,   -0x1.003e1039732a9p-4,          0x1p+0, INEXACT) // -6.460165726209976533311873936327e-02
T(RN,   -0x1.27cc5b22e42c3p-4,   -0x1.1d5ebc315411fp-4,          0x1p-1, INEXACT) // -7.221637344469926389489700113700e-02
T(RZ,   -0x1.307bceefaca9bp-4,   -0x1.25711647a6a74p-4,          0x1p+0, INEXACT) // -7.433682283844193772193165159479e-02
T(RN,   -0x1.8016ab422cd6dp-4,   -0x1.6ea153d1f2241p-4,         -0x1p-1, INEXACT) // -9.377161882257718794608791768042e-02
T(RN,    -0x1.a6a9c85b44efp-4,   -0x1.9196522d0f038p-4,         -0x1p-1, INEXACT) // -1.031892610956750555573080418981e-01
T(RZ,   -0x1.be9eacd95738dp-4,   -0x1.a721c6d62e062p-4,          0x1p+0, INEXACT) // -1.090380432046471198548331926759e-01
T(RZ,    -0x1.ca36132b4416p-4,   -0x1.b182df1ecadb3p-4,          0x1p+0, INEXACT) // -1.118679760732042005599851108855e-01
T(RN,  -0x1.079b137f36e9ep-40,  -0x1.079b137f36623p-40,         -0x1p-1, INEXACT) // -9.365158115655263657305890438656e-13
T(RN,  -0x1.1ba969c958275p-40,  -0x1.1ba969c9578a3p-40,         -0x1p-1, INEXACT) // -1.007769051937792474069225081426e-12
T(RZ,  -0x1.08000000002d6p-40,  -0x1.07ffffffffa54p-40,         0x1p-73, INEXACT) // -9.379164112034788598822847895732e-13
T(RZ,    -0x1.80000000006p-40,    -0x1.7fffffffff4p-40,       0x1.1p-71, INEXACT) // -1.364242052659702549602265979128e-12
T(RN,  -0x1.8e374d3404617p-40,  -0x1.8e374d34032bbp-40,          0x1p-1, INEXACT) // -1.414747507685445108495983313229e-12
T(RZ,  -0x1.6800000000546p-40,  -0x1.67ffffffff574p-40,       0x1.ap-72, INEXACT) // -1.278976924368452964896868063321e-12
T(RN,  -0x1.6fb79fd6e09a9p-40,  -0x1.6fb79fd6df928p-40,         -0x1p-1, INEXACT) // -1.306394220197935700109693346945e-12
T(RZ,  -0x1.da3b650e1da12p-40,  -0x1.da3b650e1be9ep-40,  0x1.cf56e8p-52, INEXACT) // -1.684810551442193721368504570182e-12
T(RZ,  -0x1.f800000000a56p-40,  -0x1.f7fffffffeb54p-40,      0x1.a8p-70, INEXACT) // -1.790567694115986823839768142390e-12
T(RZ,   -0x1.e00000000096p-40,   -0x1.dffffffffed4p-40,      0x1.58p-70, INEXACT) // -1.705302565824725122230866031841e-12
T(RZ,  -0x1.031b2d07a561bp-41,  -0x1.031b2d07a5201p-41,          0x1p+0, INEXACT) // -4.602649920770684637615174258527e-13
T(RZ,  -0x1.70c8229f43d05p-41,  -0x1.70c8229f434b7p-41,          0x1p+0, INEXACT) // -6.550880341147471535503074471234e-13
T(RZ,  -0x1.0992327adf263p-42,  -0x1.0992327adf03bp-42,          0x1p+0, INEXACT) // -2.358745046066486072623585909575e-13
T(RN,  -0x1.92a19fd3ece36p-42,  -0x1.92a19fd3ec943p-42,          0x1p-1, INEXACT) // -3.576084717497670103437019468551e-13
T(RN,  -0x1.003ff801ff659p-43,  -0x1.003ff801ff558p-43,          0x1p-1, INEXACT) // -1.137978058668471035120966809530e-13
T(RZ,  -0x1.5000000000093p-43,  -0x1.4fffffffffedap-43,          0x0p+0, INEXACT) // -1.492139745096247498346342558309e-13
T(RZ,   -0x1.eacfc33c42dcp-43,  -0x1.eacfc33c42a13p-43,  0x1.4cb99ep-52, INEXACT) // -2.179641235525554711478437307371e-13
T(RN,  -0x1.6e9b2675a667ep-44,  -0x1.6e9b2675a6577p-44,          0x1p-1, INEXACT) // -8.140289677804272690617540726857e-14
T(RN,  -0x1.68443dcc7be9fp-44,  -0x1.68443dcc7bda1p-44,          0x1p-1, INEXACT) // -7.999524775355732603496982519145e-14
T(RZ,  -0x1.ce9e5ec2bdb0bp-44,  -0x1.ce9e5ec2bd969p-44,  0x1.ece89ap-51, INEXACT) // -1.027219716917301738193750968711e-13
T(RZ,  -0x1.200000000001bp-45,  -0x1.1ffffffffffcap-45,          0x0p+0, INEXACT) // -3.197442310920467875815611977957e-14
T(RN,  -0x1.1433ec467f014p-45,  -0x1.1433ec467efc9p-45,          0x1p-1, INEXACT) // -3.066467347002827113941618819919e-14
T(RN,  -0x1.7dfea8e092241p-45,  -0x1.7dfea8e0921b3p-45,         -0x1p-1, INEXACT) // -4.240993826809857950728673304185e-14
T(RZ,  -0x1.93813088978fap-45,  -0x1.938130889785ap-45,          0x1p+0, INEXACT) // -4.479801494354726441275998402947e-14
T(RN,  -0x1.db2cfe686fec6p-45,  -0x1.db2cfe686fde9p-45,          0x1p-1, INEXACT) // -5.275510661177530590219398928485e-14
T(RZ,  -0x1.e00000000004bp-45,  -0x1.dffffffffff6ap-45,          0x0p+0, INEXACT) // -5.329070518200798725687745267544e-14
T(RN,  -0x1.419894c232a01p-46,  -0x1.419894c2329cfp-46,         -0x1p-1, INEXACT) // -1.785216529469998673086290956588e-14
T(RZ,  -0x1.465655f122fffp-47,  -0x1.465655f122fe5p-47,  0x1.f21264p-52, INEXACT) // -9.057678187205895321931969943577e-15
T(RZ,  -0x1.752e50db3a3adp-47,  -0x1.752e50db3a38bp-47,  0x1.481802p-52, INEXACT) // -1.035785127862231738137320052380e-14
T(RN,  -0x1.afb41f432003dp-47,   -0x1.afb41f432001p-47,         -0x1p-1, INEXACT) // -1.198218196950057672080642324802e-14
T(RN,  -0x1.d41ea0e98afa3p-47,  -0x1.d41ea0e98af6dp-47,          0x1p-1, INEXACT) // -1.299293014363185354831246721343e-14
T(RZ,  -0x1.6a09e667f3bd2p-48,  -0x1.6a09e667f3bc1p-48,          0x1p+0, INEXACT) // -5.024295867788084477814601612150e-15
T(RZ,  -0x1.5e8add236a594p-48,  -0x1.5e8add236a584p-48,          0x1p+0, INEXACT) // -4.864753555590498050155635744025e-15
T(RZ,  -0x1.cd82b446159fcp-48,  -0x1.cd82b446159e2p-48,  0x1.50640cp-52, INEXACT) // -6.404745667978760653336656703719e-15
T(RN,  -0x1.d64d51e0db1cap-49,  -0x1.d64d51e0db1bdp-49,         -0x1p-1, INEXACT) // -3.263375893225245720729697082594e-15
T(RN,  -0x1.b211b1c70d027p-49,  -0x1.b211b1c70d01bp-49,          0x1p-1, INEXACT) // -3.011959563148490421233065631515e-15
T(RZ,   -0x1.369a5f2538224p-5,   -0x1.30c9d57afc50ep-5,          0x1p+0, INEXACT) // -3.791540701945830815766669275035e-02
T(RZ,   -0x1.8efff3e3144f8p-5,   -0x1.85705686be91bp-5,          0x1p+0, INEXACT) // -4.870603212533269887885012394690e-02
T(RZ,   -0x1.ee9f094899bcap-5,   -0x1.dffc2a60b506cp-5,  0x1.a2aa76p-51, INEXACT) // -6.037856877519905129947375144184e-02
T(RN,  -0x1.8000000000001p-50,  -0x1.7fffffffffffdp-50,         -0x1p-1, INEXACT) // -1.332267629550188045723584306962e-15
T(RZ,  -0x1.bb67ae8584cadp-50,  -0x1.bb67ae8584ca6p-50,          0x1p+0, INEXACT) // -1.538370149106851644758381513017e-15
T(RZ,  -0x1.94c583ada5b54p-50,  -0x1.94c583ada5b4fp-50,   0x1.7fcdep-52, INEXACT) // -1.404333387430680687158478781767e-15
T(RZ,  -0x1.deeea11683f4bp-50,  -0x1.deeea11683f44p-50,  0x1.b844ccp-51, INEXACT) // -1.661629672422090128268738536011e-15
T(RZ,                -0x1p-51,  -0x1.ffffffffffffep-52,  0x1.555554p-52, INEXACT) // -4.440892098500626161694526672363e-16
T(RN,  -0x1.3988e1409212ep-51,  -0x1.3988e1409212dp-51,         -0x1p-1, INEXACT) // -5.438959822042072914295723383441e-16
T(RN,   -0x1.1984a797373d9p-6,   -0x1.171d06916a997p-6,          0x1p-1, INEXACT) // -1.718250623968118132034454959012e-02
T(RN,   -0x1.ad46640425f29p-6,   -0x1.a7b337dd52c3bp-6,         -0x1p-1, INEXACT) // -2.620086447913575269930142042085e-02
T(RZ,   -0x1.a01010113782bp-6,   -0x1.9ad307cc8629cp-6,  0x1.868436p-51, INEXACT) // -2.539445466106131019112801538995e-02
T(RZ,   -0x1.c8d3a1bf100f1p-6,    -0x1.c28448d25314p-6,          0x1p+0, INEXACT) // -2.788248820820710474621684227259e-02
T(RZ,   -0x1.14bc2b628570cp-7,   -0x1.1391dc3c70469p-7,          0x1p+0, INEXACT) // -8.445283111580013934993615976055e-03
T(RZ,   -0x1.88e63bb46a4b5p-7,   -0x1.868da0f1a9752p-7,          0x1p+0, INEXACT) // -1.199033656378598912406463483649e-02
T(RN,   -0x1.21f4ad15d2fd3p-8,   -0x1.2150b5d6f3ad3p-8,          0x1p-1, INEXACT) // -4.424373871938019724125989995400e-03
T(RZ,   -0x1.4d11d980608bdp-8,   -0x1.4c398ba0cb01ap-8,          0x1p+0, INEXACT) // -5.082240677781677158642015257328e-03
T(RZ,   -0x1.779fd1b723274p-9,   -0x1.771629fbec99dp-9,          0x1p+0, INEXACT) // -2.865785932561865437251391597329e-03
T(RZ,   -0x1.6e724b8efce88p-9,   -0x1.6def4811a9908p-9,  0x1.9733e2p-52, INEXACT) // -2.795764659362213327975510424039e-03
T(RZ,    -0x1.be95abf29f07p-9,    -0x1.bdd3211005eap-9,          0x1p+0, INEXACT) // -3.407170524324647231662055446577e-03
T(RZ,   -0x1.0a54d87783d6fp+0,   -0x1.4b1887d4d477bp-1,          0x1p+0, INEXACT) // -1.040357140711275496514076621679e+00
T(RN,   -0x1.55f885f150ad4p+0,   -0x1.795fb8be980dap-1,         -0x1p-1, INEXACT) // -1.335823413290815331322392012225e+00
T(RN,   -0x1.90c0206fe6bccp+0,   -0x1.94fe3e0155b34p-1,         -0x1p-1, INEXACT) // -1.565431620902688614194175897865e+00
T(RZ,   -0x1.0a54d87783d6fp+0,   -0x1.4b1887d4d477bp-1,          0x1p+0, INEXACT) // -1.040357140711275496514076621679e+00
T(RN,   -0x1.90c0206fe6bccp+0,   -0x1.94fe3e0155b34p-1,         -0x1p-1, INEXACT) // -1.565431620902688614194175897865e+00
T(RZ,   -0x1.1d1b02751cfe2p+5,   -0x1.ffffffffffffdp-1,  0x1.6ab188p-48, INEXACT) // -3.563818828100899338551243999973e+01
T(RN,   -0x1.1bdf4f1b18e0fp+5,   -0x1.ffffffffffffcp-1,          0x1p-1, INEXACT) // -3.548403760118173266846497426741e+01
T(RN,   -0x1.19dc9df7850b1p+5,   -0x1.ffffffffffffbp-1,          0x1p-1, INEXACT) // -3.523272317290082611407342483290e+01
T(RN,   -0x1.1841a4bab2d6dp+5,   -0x1.ffffffffffffap-1,          0x1p-1, INEXACT) // -3.503205247743867545295870513655e+01
T(RN,   -0x1.14c61cb0378eap+5,   -0x1.ffffffffffff7p-1,          0x1p-1, INEXACT) // -3.459673440618082906894414918497e+01
T(RN,   -0x1.125b0a74605a3p+5,   -0x1.ffffffffffff5p-1,         -0x1p-1, INEXACT) // -3.429445353430789822368751629256e+01
T(RN,   -0x1.0e8d5f83f7466p+5,   -0x1.fffffffffffedp-1,          0x1p-1, INEXACT) // -3.381902983759282221853936789557e+01
T(RN,   -0x1.0a0b634b09bb3p+5,   -0x1.fffffffffffdfp-1,          0x1p-1, INEXACT) // -3.325556048034140843583372770809e+01
T(RN,   -0x1.072dc4ec4a614p+5,   -0x1.fffffffffffd2p-1,         -0x1p-1, INEXACT) // -3.289734825708379162279015872627e+01
T(RZ,   -0x1.06ecbf7622c43p+5,    -0x1.fffffffffffdp-1,  0x1.1ebefep-44, INEXACT) // -3.286559955876921179651617421769e+01
T(RN,   -0x1.05e8a70c2f641p+5,   -0x1.fffffffffffc9p-1,          0x1p-1, INEXACT) // -3.273859986800790267125194077380e+01
T(RZ,    -0x1.05b10c1c1ea7p+5,   -0x1.fffffffffffc7p-1,          0x1p+0, INEXACT) // -3.271144887894195107946870848536e+01
T(RN,   -0x1.0414697c870cep+5,   -0x1.fffffffffffbbp-1,          0x1p-1, INEXACT) // -3.250996682440892016074940329418e+01
T(RZ,   -0x1.03e80c9fa4fd6p+5,   -0x1.fffffffffffb9p-1,          0x1p+0, INEXACT) // -3.248830532762774225830071372911e+01
T(RZ,   -0x1.03caffca29d21p+5,   -0x1.fffffffffffb9p-1,   0x1.c85ddp-47, INEXACT) // -3.247412069263578615618826006539e+01
T(RN,   -0x1.03d979054a9bep+5,   -0x1.fffffffffffb9p-1,          0x1p-1, INEXACT) // -3.248118785985887768674729159102e+01
T(RZ,   -0x1.03ae5af88ad12p+5,   -0x1.fffffffffffb7p-1,          0x1p+0, INEXACT) // -3.246013445066104452507715905085e+01
T(RN,   -0x1.03842086a9324p+5,   -0x1.fffffffffffb6p-1,          0x1p-1, INEXACT) // -3.243951516345831009857647586614e+01
T(RZ,   -0x1.033fa02cf1af8p+5,   -0x1.fffffffffffb4p-1,  0x1.80e07ep-44, INEXACT) // -3.240606722939077144474140368402e+01
T(RZ,   -0x1.02bd22bd19799p+5,   -0x1.fffffffffffafp-1,  0x1.28e2b8p-43, INEXACT) // -3.234235141500466426123239216395e+01
T(RZ,   -0x1.021361bbb89cep+5,   -0x1.fffffffffffa7p-1,          0x1p+0, INEXACT) // -3.225946375519889386396243935451e+01
T(RN,   -0x1.021f0d232b53cp+5,   -0x1.fffffffffffa9p-1,         -0x1p-1, INEXACT) // -3.226516177631353343713271897286e+01
T(RZ,   -0x1.01e55b7c11278p+5,   -0x1.fffffffffffa5p-1,          0x1p+0, INEXACT) // -3.223699089934683570390916429460e+01
T(RN,   -0x1.01f0c451137d7p+5,   -0x1.fffffffffffa7p-1,         -0x1p-1, INEXACT) // -3.224256194439629297221472370438e+01
T(RN,   -0x1.01c3815eb6b48p+5,   -0x1.fffffffffffa5p-1,         -0x1p-1, INEXACT) // -3.222046159739562654067412950099e+01
T(RN,   -0x1.01816f63155c6p+5,   -0x1.fffffffffffa1p-1,          0x1p-1, INEXACT) // -3.218820073517740354418492643163e+01
T(RZ,   -0x1.004a623f3ef34p+5,   -0x1.fffffffffff91p-1,          0x1p+0, INEXACT) // -3.203632020388468504279444459826e+01
T(RN,   -0x1.002ea52c1fd9bp+5,    -0x1.fffffffffff9p-1,          0x1p-1, INEXACT) // -3.202277597877692727479370660149e+01
T(RN,   -0x1.001c5bff977dep+5,    -0x1.fffffffffff9p-1,         -0x1p-1, INEXACT) // -3.201384734803262688274116953835e+01
T(RZ,   -0x1.00013baf59bc7p+5,   -0x1.fffffffffff8dp-1,          0x1p+0, INEXACT) // -3.200060212128260417330238851719e+01
T(RN,   -0x1.fe584d79c245cp+4,   -0x1.fffffffffff81p-1,          0x1p-1, INEXACT) // -3.189655826150952577791031217203e+01
T(RZ,   -0x1.fda9fa7c4153bp+4,   -0x1.fffffffffff7bp-1,          0x1p+0, INEXACT) // -3.185399864709073014523710298818e+01
T(RZ,   -0x1.fd8b10aaab3e9p+4,   -0x1.fffffffffff7ap-1,          0x1p+0, INEXACT) // -3.184645144145534700896860158537e+01
T(RZ,   -0x1.fd4dedfcf268fp+4,   -0x1.fffffffffff79p-1,  0x1.5314cep-48, INEXACT) // -3.183152579123867198518382792827e+01
T(RN,   -0x1.fce5171c90d01p+4,   -0x1.fffffffffff76p-1,         -0x1p-1, INEXACT) // -3.180593024404970847740514727775e+01
T(RZ,   -0x1.fc0d1518e122bp+4,   -0x1.fffffffffff6dp-1,          0x1p+0, INEXACT) // -3.175319394796876437681021343451e+01
T(RN,   -0x1.fb5aab402cdedp+4,   -0x1.fffffffffff67p-1,          0x1p-1, INEXACT) // -3.170963597362963426462556526531e+01
T(RZ,   -0x1.fa17fb834e007p+4,   -0x1.fffffffffff5bp-1,  0x1.8d90c4p-44, INEXACT) // -3.163085509577652132406910823192e+01
T(RN,   -0x1.f9c2019d062bap+4,   -0x1.fffffffffff57p-1,          0x1p-1, INEXACT) // -3.160986481988468455028851167299e+01
T(RZ,   -0x1.f8e15986afb67p+4,   -0x1.fffffffffff4dp-1,          0x1p+0, INEXACT) // -3.155501701938501568633910210337e+01
T(RN,   -0x1.f87b161fedcf7p+4,   -0x1.fffffffffff4ap-1,         -0x1p-1, INEXACT) // -3.153005039665455555564221867826e+01
T(RN,   -0x1.f8384d65ed489p+4,   -0x1.fffffffffff47p-1,         -0x1p-1, INEXACT) // -3.151374568762961203560735157225e+01
T(RN,   -0x1.f7e0eaeda9ca7p+4,   -0x1.fffffffffff43p-1,         -0x1p-1, INEXACT) // -3.149241154515462071117326559033e+01
T(RZ,   -0x1.f76bba9be9566p+4,   -0x1.fffffffffff3cp-1,          0x1p+0, INEXACT) // -3.146380101111335392261025845073e+01
T(RZ,   -0x1.f6c70b1f18a8bp+4,   -0x1.fffffffffff35p-1,  0x1.6827fep-44, INEXACT) // -3.142359459063531446076922293287e+01
T(RZ,   -0x1.f64fbbe9df2a5p+4,   -0x1.fffffffffff2ep-1,          0x1p+0, INEXACT) // -3.139446631771228979346233245451e+01
T(RN,   -0x1.f54f5a8dbc633p+4,   -0x1.fffffffffff22p-1,         -0x1p-1, INEXACT) // -3.133187346807080686517110734712e+01
T(RN,   -0x1.f53cfc69477c8p+4,   -0x1.fffffffffff21p-1,         -0x1p-1, INEXACT) // -3.132738915562347870036319363862e+01
T(RN,   -0x1.f4e25ce18030cp+4,   -0x1.fffffffffff1cp-1,         -0x1p-1, INEXACT) // -3.130526435934284279483108548447e+01
T(RN,   -0x1.f4783271917d3p+4,   -0x1.fffffffffff16p-1,         -0x1p-1, INEXACT) // -3.127934498179076783230811997782e+01
T(RZ,   -0x1.f45e147ed01f7p+4,   -0x1.fffffffffff13p-1,          0x1p+0, INEXACT) // -3.127296876465149111368191370275e+01
T(RN,   -0x1.f432eb1ec59cdp+4,   -0x1.fffffffffff11p-1,          0x1p-1, INEXACT) // -3.126243125934870548121580213774e+01
T(RZ,   -0x1.f38272b4ae6a3p+4,   -0x1.fffffffffff06p-1,          0x1p+0, INEXACT) // -3.121934767321239334592064551543e+01
T(RZ,   -0x1.f3310393e9294p+4,   -0x1.fffffffffff01p-1,          0x1p+0, INEXACT) // -3.119946630265856413188885198906e+01
T(RN,   -0x1.f33915bcf0e7fp+4,   -0x1.fffffffffff03p-1,         -0x1p-1, INEXACT) // -3.120143674664586441735991684254e+01
T(RZ,   -0x1.f320eb6e57701p+4,     -0x1.fffffffffffp-1,          0x1p+0, INEXACT) // -3.119553702451867494005455228034e+01
T(RN,   -0x1.f328f57b126ffp+4,   -0x1.fffffffffff01p-1,          0x1p-1, INEXACT) // -3.119749973368652362637476471718e+01
