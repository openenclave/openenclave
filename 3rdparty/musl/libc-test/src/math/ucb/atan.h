// Copyright (C) 1988-1994 Sun Microsystems, Inc. 2550 Garcia Avenue
// Mountain View, California  94043 All rights reserved.
//
// Any person is hereby authorized to download, copy, use, create bug fixes,
// and distribute, subject to the following conditions:
//
// 	1.  the software may not be redistributed for a fee except as
// 	    reasonable to cover media costs;
// 	2.  any copy of the software must include this notice, as well as
// 	    any other embedded copyright notices; and
// 	3.  any distribution of this software or derivative works thereof
// 	    must comply with all applicable U.S. export control laws.
//
// THE SOFTWARE IS MADE AVAILABLE "AS IS" AND WITHOUT EXPRESS OR IMPLIED
// WARRANTY OF ANY KIND, INCLUDING BUT NOT LIMITED TO THE IMPLIED
// WARRANTIES OF DESIGN, MERCHANTIBILITY, FITNESS FOR A PARTICULAR
// PURPOSE, NON-INFRINGEMENT, PERFORMANCE OR CONFORMANCE TO
// SPECIFICATIONS.
//
// BY DOWNLOADING AND/OR USING THIS SOFTWARE, THE USER WAIVES ALL CLAIMS
// AGAINST SUN MICROSYSTEMS, INC. AND ITS AFFILIATED COMPANIES IN ANY
// JURISDICTION, INCLUDING BUT NOT LIMITED TO CLAIMS FOR DAMAGES OR
// EQUITABLE RELIEF BASED ON LOSS OF DATA, AND SPECIFICALLY WAIVES EVEN
// UNKNOWN OR UNANTICIPATED CLAIMS OR LOSSES, PRESENT AND FUTURE.
//
// IN NO EVENT WILL SUN MICROSYSTEMS, INC. OR ANY OF ITS AFFILIATED
// COMPANIES BE LIABLE FOR ANY LOST REVENUE OR PROFITS OR OTHER SPECIAL,
// INDIRECT AND CONSEQUENTIAL DAMAGES, EVEN IF IT HAS BEEN ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGES.
//
// This file is provided with no support and without any obligation on the
// part of Sun Microsystems, Inc. ("Sun") or any of its affiliated
// companies to assist in its use, correction, modification or
// enhancement.  Nevertheless, and without creating any obligation on its
// part, Sun welcomes your comments concerning the software and requests
// that they be sent to fdlibm-comments@sunpro.sun.com.
// atand(+-max) is +-pi/2
T(RN, 0x1.fffffffffffffp+1023,    0x1.921fb54442d18p+0,  -0x1.1a6264p-2, INEXACT)
T(RN,-0x1.fffffffffffffp+1023,   -0x1.921fb54442d18p+0,   0x1.1a6264p-2, INEXACT)
// atand(+-1) is +-pi/4
T(RN,                  0x1p+0,    0x1.921fb54442d18p-1,  -0x1.1a6264p-2, INEXACT)
T(RN,                 -0x1p+0,   -0x1.921fb54442d18p-1,   0x1.1a6264p-2, INEXACT)
// atand(tiny) is tiny
T(RN,                 0x1p-30,                 0x1p-30,  0x1.555556p-10, INEXACT)
T(RN,                -0x1p-30,                -0x1p-30, -0x1.555556p-10, INEXACT)
T(RN,               0x1p-1022,               0x1p-1022,          0x0p+0, INEXACT)
T(RN,              -0x1p-1022,              -0x1p-1022,          0x0p+0, INEXACT)
T(RZ,                 0x1p-30,   0x1.fffffffffffffp-31,  -0x1.feaaaap-1, INEXACT)
T(RZ,                -0x1p-30,  -0x1.fffffffffffffp-31,   0x1.feaaaap-1, INEXACT)
T(RZ,               0x1p-1022, 0x1.ffffffffffffep-1023,         -0x1p+0, INEXACT|UNDERFLOW)
T(RZ,              -0x1p-1022,-0x1.ffffffffffffep-1023,          0x1p+0, INEXACT|UNDERFLOW)
T(RU,                 0x1p-30,                 0x1p-30,  0x1.555556p-10, INEXACT)
T(RU,                -0x1p-30,  -0x1.fffffffffffffp-31,   0x1.feaaaap-1, INEXACT)
T(RU,               0x1p-1022,               0x1p-1022,          0x0p+0, INEXACT)
T(RU,              -0x1p-1022,-0x1.ffffffffffffep-1023,          0x1p+0, INEXACT|UNDERFLOW)
T(RD,                 0x1p-30,   0x1.fffffffffffffp-31,  -0x1.feaaaap-1, INEXACT)
T(RD,                -0x1p-30,                -0x1p-30, -0x1.555556p-10, INEXACT)
T(RD,               0x1p-1022, 0x1.ffffffffffffep-1023,         -0x1p+0, INEXACT|UNDERFLOW)
T(RD,              -0x1p-1022,              -0x1p-1022,          0x0p+0, INEXACT)
// atand(+-0) is +-0
T(RN,                  0x0p+0,                  0x0p+0,          0x0p+0, 0)
T(RN,                 -0x0p+0,                 -0x0p+0,          0x0p+0, 0)
T(RZ,                  0x0p+0,                  0x0p+0,          0x0p+0, 0)
T(RZ,                 -0x0p+0,                 -0x0p+0,          0x0p+0, 0)
T(RU,                  0x0p+0,                  0x0p+0,          0x0p+0, 0)
T(RU,                 -0x0p+0,                 -0x0p+0,          0x0p+0, 0)
T(RD,                  0x0p+0,                  0x0p+0,          0x0p+0, 0)
T(RD,                 -0x0p+0,                 -0x0p+0,          0x0p+0, 0)
// random arguments between -2 and 2
T(RN,   -0x1.13284b2b5006dp-1,   -0x1.f8f75bb5fd451p-2,  0x1.0a1192p-11, INEXACT)
T(RN,    0x1.6ca8dfb825911p+0,    0x1.eadc6ce9cba6cp-1,  -0x1.897aaep-5, INEXACT)
T(RN,    0x1.c2ca609de7505p+0,    0x1.0de7f90a2292bp+0,  -0x1.adec12p-2, INEXACT)
T(RN,   -0x1.55f11fba96889p+0,    -0x1.db367aed1093p-1,   0x1.1aa32cp-3, INEXACT)
T(RN,   -0x1.15679e27084ddp-1,    -0x1.fc72849d05c9p-2,   0x1.4db836p-2, INEXACT)
T(RN,   -0x1.41e131b093c41p-4,   -0x1.413832eb4f31dp-4,  -0x1.06e782p-6, INEXACT)
T(RN,    0x1.281b0d18455f5p+0,    0x1.b74040cba5c63p-1,  -0x1.881588p-2, INEXACT)
T(RN,    0x1.b5ce34a51b239p+0,    0x1.0aab58c02e298p+0,  -0x1.35666ep-2, INEXACT)
T(RN,   -0x1.583481079de4dp-2,   -0x1.4c0e12c6c30bfp-2,   0x1.188ba8p-2, INEXACT)
T(RN,   -0x1.ea8223103b871p+0,   -0x1.16fb9ae45d4fcp+0,  -0x1.a14c14p-2, INEXACT)
T(RZ,   -0x1.13284b2b5006dp-1,   -0x1.f8f75bb5fd451p-2,  0x1.0a1192p-11, INEXACT)
T(RZ,    0x1.6ca8dfb825911p+0,    0x1.eadc6ce9cba6cp-1,  -0x1.897aaep-5, INEXACT)
T(RZ,    0x1.c2ca609de7505p+0,    0x1.0de7f90a2292bp+0,  -0x1.adec12p-2, INEXACT)
T(RU,   -0x1.55f11fba96889p+0,    -0x1.db367aed1093p-1,   0x1.1aa32cp-3, INEXACT)
T(RU,   -0x1.15679e27084ddp-1,    -0x1.fc72849d05c9p-2,   0x1.4db836p-2, INEXACT)
T(RU,   -0x1.41e131b093c41p-4,   -0x1.413832eb4f31cp-4,   0x1.f7c8c4p-1, INEXACT)
T(RD,    0x1.281b0d18455f5p+0,    0x1.b74040cba5c63p-1,  -0x1.881588p-2, INEXACT)
T(RD,    0x1.b5ce34a51b239p+0,    0x1.0aab58c02e298p+0,  -0x1.35666ep-2, INEXACT)
T(RD,   -0x1.583481079de4dp-2,    -0x1.4c0e12c6c30cp-2,  -0x1.73ba2cp-1, INEXACT)
T(RD,   -0x1.ea8223103b871p+0,   -0x1.16fb9ae45d4fcp+0,  -0x1.a14c14p-2, INEXACT)
// atand(+-inf) is +-pi/2
T(RN,                     inf,    0x1.921fb54442d18p+0,  -0x1.1a6264p-2, INEXACT)
T(RN,                    -inf,   -0x1.921fb54442d18p+0,   0x1.1a6264p-2, INEXACT)
// atand(nan) is nan
T(RN,                     nan,                     nan,          0x0p+0, 0)
T(RN,                     nan,                     nan,          0x0p+0, 0)
T(RZ,                     nan,                     nan,          0x0p+0, 0)
T(RZ,                     nan,                     nan,          0x0p+0, 0)
T(RU,                     nan,                     nan,          0x0p+0, 0)
T(RU,                     nan,                     nan,          0x0p+0, 0)
T(RD,                     nan,                     nan,          0x0p+0, 0)
T(RD,                     nan,                     nan,          0x0p+0, 0)
T(RD, 0x1.0000000000001p-1022,               0x1p-1022,         -0x1p+0, INEXACT)
T(RD, 0x1.0000000000002p-1022, 0x1.0000000000001p-1022,         -0x1p+0, INEXACT)
T(RD,               0x1p-1021, 0x1.fffffffffffffp-1022,         -0x1p+0, INEXACT)
T(RD,               0x1p-1020, 0x1.fffffffffffffp-1021,         -0x1p+0, INEXACT)
T(RD,-0x1.0000000000001p-1022,-0x1.0000000000001p-1022,          0x0p+0, INEXACT)
T(RD,-0x1.0000000000002p-1022,-0x1.0000000000002p-1022,          0x0p+0, INEXACT)
T(RD,-0x1.ffffffffffffbp-1022,-0x1.ffffffffffffbp-1022,          0x0p+0, INEXACT)
T(RD,              -0x1p-1021,              -0x1p-1021,          0x0p+0, INEXACT)
T(RD,-0x1.0000000000003p-1021,-0x1.0000000000003p-1021,          0x0p+0, INEXACT)
T(RD,              -0x1p-1020,              -0x1p-1020,          0x0p+0, INEXACT)
T(RD,               0x1p-1074,                  0x0p+0,         -0x1p+0, INEXACT|UNDERFLOW)
T(RD,               0x1p-1073,               0x1p-1074,         -0x1p+0, INEXACT|UNDERFLOW)
T(RD,               0x1p-1024, 0x1.ffffffffffff8p-1025,         -0x1p+0, INEXACT|UNDERFLOW)
T(RD,               0x1p-1023, 0x1.ffffffffffffcp-1024,         -0x1p+0, INEXACT|UNDERFLOW)
T(RD, 0x1.ffffffffffffcp-1023, 0x1.ffffffffffffap-1023,         -0x1p+0, INEXACT|UNDERFLOW)
T(RD, 0x1.ffffffffffffep-1023, 0x1.ffffffffffffcp-1023,         -0x1p+0, INEXACT|UNDERFLOW)
T(RD,              -0x1p-1074,              -0x1p-1074,          0x0p+0, INEXACT|UNDERFLOW)
T(RD,              -0x1p-1073,              -0x1p-1073,          0x0p+0, INEXACT|UNDERFLOW)
T(RD,            -0x1.2p-1071,            -0x1.2p-1071,          0x0p+0, INEXACT|UNDERFLOW)
T(RD,              -0x1p-1024,              -0x1p-1024,          0x0p+0, INEXACT|UNDERFLOW)
T(RD,              -0x1p-1023,              -0x1p-1023,          0x0p+0, INEXACT|UNDERFLOW)
T(RD,-0x1.ffffffffffffcp-1023,-0x1.ffffffffffffcp-1023,          0x0p+0, INEXACT|UNDERFLOW)
T(RD,-0x1.ffffffffffffep-1023,-0x1.ffffffffffffep-1023,          0x0p+0, INEXACT|UNDERFLOW)
T(RD,               0x1.8p-27,   0x1.7ffffffffffffp-27,       -0x1.7p-1, INEXACT)
T(RD,              -0x1.8p-27,              -0x1.8p-27,       -0x1.2p-2, INEXACT)
T(RN, 0x1.0000000000001p-1022, 0x1.0000000000001p-1022,          0x0p+0, INEXACT)
T(RN, 0x1.0000000000002p-1022, 0x1.0000000000002p-1022,          0x0p+0, INEXACT)
T(RN, 0x1.ffffffffffffbp-1022, 0x1.ffffffffffffbp-1022,          0x0p+0, INEXACT)
T(RN,               0x1p-1021,               0x1p-1021,          0x0p+0, INEXACT)
T(RN, 0x1.0000000000003p-1021, 0x1.0000000000003p-1021,          0x0p+0, INEXACT)
T(RN,               0x1p-1020,               0x1p-1020,          0x0p+0, INEXACT)
T(RN,               0x1.8p-27,               0x1.8p-27,        0x1.2p-2, INEXACT)
T(RN,-0x1.0000000000001p-1022,-0x1.0000000000001p-1022,          0x0p+0, INEXACT)
T(RN,-0x1.0000000000002p-1022,-0x1.0000000000002p-1022,          0x0p+0, INEXACT)
T(RN,-0x1.ffffffffffffbp-1022,-0x1.ffffffffffffbp-1022,          0x0p+0, INEXACT)
T(RN,              -0x1p-1021,              -0x1p-1021,          0x0p+0, INEXACT)
T(RN,-0x1.0000000000003p-1021,-0x1.0000000000003p-1021,          0x0p+0, INEXACT)
T(RN,              -0x1p-1020,              -0x1p-1020,          0x0p+0, INEXACT)
T(RN,              -0x1.8p-27,              -0x1.8p-27,       -0x1.2p-2, INEXACT)
T(RN,               0x1p-1074,               0x1p-1074,          0x0p+0, INEXACT|UNDERFLOW)
T(RN,               0x1p-1073,               0x1p-1073,          0x0p+0, INEXACT|UNDERFLOW)
T(RN,             0x1.2p-1071,             0x1.2p-1071,          0x0p+0, INEXACT|UNDERFLOW)
T(RN,               0x1p-1024,               0x1p-1024,          0x0p+0, INEXACT|UNDERFLOW)
T(RN,               0x1p-1023,               0x1p-1023,          0x0p+0, INEXACT|UNDERFLOW)
T(RN, 0x1.ffffffffffffcp-1023, 0x1.ffffffffffffcp-1023,          0x0p+0, INEXACT|UNDERFLOW)
T(RN, 0x1.ffffffffffffep-1023, 0x1.ffffffffffffep-1023,          0x0p+0, INEXACT|UNDERFLOW)
T(RN,              -0x1p-1074,              -0x1p-1074,          0x0p+0, INEXACT|UNDERFLOW)
T(RN,              -0x1p-1073,              -0x1p-1073,          0x0p+0, INEXACT|UNDERFLOW)
T(RN,            -0x1.2p-1071,            -0x1.2p-1071,          0x0p+0, INEXACT|UNDERFLOW)
T(RN,              -0x1p-1024,              -0x1p-1024,          0x0p+0, INEXACT|UNDERFLOW)
T(RN,              -0x1p-1023,              -0x1p-1023,          0x0p+0, INEXACT|UNDERFLOW)
T(RN,-0x1.ffffffffffffcp-1023,-0x1.ffffffffffffcp-1023,          0x0p+0, INEXACT|UNDERFLOW)
T(RN,-0x1.ffffffffffffep-1023,-0x1.ffffffffffffep-1023,          0x0p+0, INEXACT|UNDERFLOW)
T(RU, 0x1.0000000000001p-1022, 0x1.0000000000001p-1022,          0x0p+0, INEXACT)
T(RU, 0x1.0000000000002p-1022, 0x1.0000000000002p-1022,          0x0p+0, INEXACT)
T(RU, 0x1.ffffffffffffbp-1022, 0x1.ffffffffffffbp-1022,          0x0p+0, INEXACT)
T(RU,               0x1p-1021,               0x1p-1021,          0x0p+0, INEXACT)
T(RU, 0x1.0000000000003p-1021, 0x1.0000000000003p-1021,          0x0p+0, INEXACT)
T(RU,               0x1p-1020,               0x1p-1020,          0x0p+0, INEXACT)
T(RU,-0x1.0000000000001p-1022,              -0x1p-1022,          0x1p+0, INEXACT)
T(RU,-0x1.0000000000002p-1022,-0x1.0000000000001p-1022,          0x1p+0, INEXACT)
T(RU,              -0x1p-1021,-0x1.fffffffffffffp-1022,          0x1p+0, INEXACT)
T(RU,              -0x1p-1020,-0x1.fffffffffffffp-1021,          0x1p+0, INEXACT)
T(RU,               0x1p-1074,               0x1p-1074,          0x0p+0, INEXACT|UNDERFLOW)
T(RU,               0x1p-1073,               0x1p-1073,          0x0p+0, INEXACT|UNDERFLOW)
T(RU,             0x1.2p-1071,             0x1.2p-1071,          0x0p+0, INEXACT|UNDERFLOW)
T(RU,               0x1p-1024,               0x1p-1024,          0x0p+0, INEXACT|UNDERFLOW)
T(RU,               0x1p-1023,               0x1p-1023,          0x0p+0, INEXACT|UNDERFLOW)
T(RU, 0x1.ffffffffffffcp-1023, 0x1.ffffffffffffcp-1023,          0x0p+0, INEXACT|UNDERFLOW)
T(RU, 0x1.ffffffffffffep-1023, 0x1.ffffffffffffep-1023,          0x0p+0, INEXACT|UNDERFLOW)
T(RU,              -0x1p-1074,                 -0x0p+0,          0x1p+0, INEXACT|UNDERFLOW)
T(RU,              -0x1p-1073,              -0x1p-1074,          0x1p+0, INEXACT|UNDERFLOW)
T(RU,              -0x1p-1024,-0x1.ffffffffffff8p-1025,          0x1p+0, INEXACT|UNDERFLOW)
T(RU,              -0x1p-1023,-0x1.ffffffffffffcp-1024,          0x1p+0, INEXACT|UNDERFLOW)
T(RU,-0x1.ffffffffffffcp-1023,-0x1.ffffffffffffap-1023,          0x1p+0, INEXACT|UNDERFLOW)
T(RU,-0x1.ffffffffffffep-1023,-0x1.ffffffffffffcp-1023,          0x1p+0, INEXACT|UNDERFLOW)
T(RU,               0x1.8p-27,               0x1.8p-27,        0x1.2p-2, INEXACT)
T(RU,              -0x1.8p-27,  -0x1.7ffffffffffffp-27,        0x1.7p-1, INEXACT)
T(RZ, 0x1.0000000000001p-1022,               0x1p-1022,         -0x1p+0, INEXACT)
T(RZ, 0x1.0000000000002p-1022, 0x1.0000000000001p-1022,         -0x1p+0, INEXACT)
T(RZ,               0x1p-1021, 0x1.fffffffffffffp-1022,         -0x1p+0, INEXACT)
T(RZ,               0x1p-1020, 0x1.fffffffffffffp-1021,         -0x1p+0, INEXACT)
T(RZ,-0x1.0000000000001p-1022,              -0x1p-1022,          0x1p+0, INEXACT)
T(RZ,-0x1.0000000000002p-1022,-0x1.0000000000001p-1022,          0x1p+0, INEXACT)
T(RZ,              -0x1p-1021,-0x1.fffffffffffffp-1022,          0x1p+0, INEXACT)
T(RZ,              -0x1p-1020,-0x1.fffffffffffffp-1021,          0x1p+0, INEXACT)
T(RZ,               0x1p-1074,                  0x0p+0,         -0x1p+0, INEXACT|UNDERFLOW)
T(RZ,               0x1p-1073,               0x1p-1074,         -0x1p+0, INEXACT|UNDERFLOW)
T(RZ,               0x1p-1024, 0x1.ffffffffffff8p-1025,         -0x1p+0, INEXACT|UNDERFLOW)
T(RZ,               0x1p-1023, 0x1.ffffffffffffcp-1024,         -0x1p+0, INEXACT|UNDERFLOW)
T(RZ, 0x1.ffffffffffffcp-1023, 0x1.ffffffffffffap-1023,         -0x1p+0, INEXACT|UNDERFLOW)
T(RZ, 0x1.ffffffffffffep-1023, 0x1.ffffffffffffcp-1023,         -0x1p+0, INEXACT|UNDERFLOW)
T(RZ,              -0x1p-1074,                 -0x0p+0,          0x1p+0, INEXACT|UNDERFLOW)
T(RZ,              -0x1p-1073,              -0x1p-1074,          0x1p+0, INEXACT|UNDERFLOW)
T(RZ,              -0x1p-1024,-0x1.ffffffffffff8p-1025,          0x1p+0, INEXACT|UNDERFLOW)
T(RZ,              -0x1p-1023,-0x1.ffffffffffffcp-1024,          0x1p+0, INEXACT|UNDERFLOW)
T(RZ,-0x1.ffffffffffffcp-1023,-0x1.ffffffffffffap-1023,          0x1p+0, INEXACT|UNDERFLOW)
T(RZ,-0x1.ffffffffffffep-1023,-0x1.ffffffffffffcp-1023,          0x1p+0, INEXACT|UNDERFLOW)
T(RZ,               0x1.8p-27,   0x1.7ffffffffffffp-27,       -0x1.7p-1, INEXACT)
T(RZ,              -0x1.8p-27,  -0x1.7ffffffffffffp-27,        0x1.7p-1, INEXACT)
