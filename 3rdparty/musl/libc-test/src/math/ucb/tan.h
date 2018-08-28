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
// tand(+-max)
// tand(tiny) is tiny
T(RN,                 0x1p-30,                 0x1p-30, -0x1.555556p-10, INEXACT)
T(RN,                -0x1p-30,                -0x1p-30,  0x1.555556p-10, INEXACT)
T(RN,               0x1p-1022,               0x1p-1022,          0x0p+0, INEXACT)
T(RN,              -0x1p-1022,              -0x1p-1022,          0x0p+0, INEXACT)
T(RN,               0x1p-1074,               0x1p-1074,          0x0p+0, INEXACT|UNDERFLOW)
T(RN,              -0x1p-1074,              -0x1p-1074,          0x0p+0, INEXACT|UNDERFLOW)
T(RN,                  0x0p+0,                  0x0p+0,          0x0p+0, 0)
T(RN,                 -0x0p+0,                 -0x0p+0,          0x0p+0, 0)
T(RZ,                  0x0p+0,                  0x0p+0,          0x0p+0, 0)
T(RZ,                 -0x0p+0,                 -0x0p+0,          0x0p+0, 0)
T(RU,                  0x0p+0,                  0x0p+0,          0x0p+0, 0)
T(RU,                 -0x0p+0,                 -0x0p+0,          0x0p+0, 0)
T(RD,                  0x0p+0,                  0x0p+0,          0x0p+0, 0)
T(RD,                 -0x0p+0,                 -0x0p+0,          0x0p+0, 0)
// tand(nan or inf) is nan
T(RN,                     inf,                     nan,          0x0p+0, INVALID)
T(RN,                    -inf,                     nan,          0x0p+0, INVALID)
T(RN,                     nan,                     nan,          0x0p+0, 0)
T(RN,                     nan,                     nan,          0x0p+0, 0)
// tand(+-pi/4) is +-1 within 16 ulp
T(RN,    0x1.921fb54442d18p-1,    0x1.fffffffffffffp-1,  -0x1.cb3b3ap-2, INEXACT)
T(RN,   -0x1.921fb54442d18p-1,   -0x1.fffffffffffffp-1,   0x1.cb3b3ap-2, INEXACT)
T(RZ,    0x1.921fb54442d18p-1,    0x1.fffffffffffffp-1,  -0x1.cb3b3ap-2, INEXACT)
T(RZ,   -0x1.921fb54442d18p-1,   -0x1.fffffffffffffp-1,   0x1.cb3b3ap-2, INEXACT)
T(RU,    0x1.921fb54442d18p-1,                  0x1p+0,   0x1.1a6264p-2, INEXACT)
T(RU,   -0x1.921fb54442d18p-1,   -0x1.fffffffffffffp-1,   0x1.cb3b3ap-2, INEXACT)
T(RD,    0x1.921fb54442d18p-1,    0x1.fffffffffffffp-1,  -0x1.cb3b3ap-2, INEXACT)
T(RD,   -0x1.921fb54442d18p-1,                 -0x1p+0,  -0x1.1a6264p-2, INEXACT)
T(RD,               0x1p-1022,               0x1p-1022,          0x0p+0, INEXACT)
T(RD, 0x1.0000000000001p-1022, 0x1.0000000000001p-1022,          0x0p+0, INEXACT)
T(RD, 0x1.0000000000002p-1022, 0x1.0000000000002p-1022,          0x0p+0, INEXACT)
T(RD, 0x1.ffffffffffffbp-1022, 0x1.ffffffffffffbp-1022,          0x0p+0, INEXACT)
T(RD,               0x1p-1021,               0x1p-1021,          0x0p+0, INEXACT)
T(RD, 0x1.0000000000003p-1021, 0x1.0000000000003p-1021,          0x0p+0, INEXACT)
T(RD,               0x1p-1020,               0x1p-1020,          0x0p+0, INEXACT)
T(RD,               0x1.8p-27,               0x1.8p-27,       -0x1.2p-2, INEXACT)
T(RD,                 0x1p-26,                 0x1p-26,  -0x1.555556p-2, INEXACT)
T(RD,               0x1p-1074,               0x1p-1074,          0x0p+0, INEXACT|UNDERFLOW)
T(RD,               0x1p-1073,               0x1p-1073,          0x0p+0, INEXACT|UNDERFLOW)
T(RD,             0x1.2p-1071,             0x1.2p-1071,          0x0p+0, INEXACT|UNDERFLOW)
T(RD,               0x1p-1024,               0x1p-1024,          0x0p+0, INEXACT|UNDERFLOW)
T(RD,               0x1p-1023,               0x1p-1023,          0x0p+0, INEXACT|UNDERFLOW)
T(RD, 0x1.ffffffffffffcp-1023, 0x1.ffffffffffffcp-1023,          0x0p+0, INEXACT|UNDERFLOW)
T(RD, 0x1.ffffffffffffep-1023, 0x1.ffffffffffffep-1023,          0x0p+0, INEXACT|UNDERFLOW)
T(RD,                     nan,                     nan,          0x0p+0, 0)
T(RD,                     nan,                     nan,          0x0p+0, 0)
T(RD,                     inf,                     nan,          0x0p+0, INVALID)
T(RD,                    -inf,                     nan,          0x0p+0, INVALID)
T(RD,              -0x1p-1022,-0x1.0000000000001p-1022,         -0x1p+0, INEXACT)
T(RD,-0x1.0000000000001p-1022,-0x1.0000000000002p-1022,         -0x1p+0, INEXACT)
T(RD,-0x1.0000000000002p-1022,-0x1.0000000000003p-1022,         -0x1p+0, INEXACT)
T(RD,              -0x1p-1021,-0x1.0000000000001p-1021,         -0x1p+0, INEXACT)
T(RD,              -0x1p-1020,-0x1.0000000000001p-1020,         -0x1p+0, INEXACT)
T(RD,              -0x1.8p-27,  -0x1.8000000000001p-27,       -0x1.7p-1, INEXACT)
T(RD,                -0x1p-26,  -0x1.0000000000001p-26,  -0x1.555556p-1, INEXACT)
T(RD,              -0x1p-1074,              -0x1p-1073,         -0x1p+0, INEXACT|UNDERFLOW)
T(RD,              -0x1p-1073,            -0x1.8p-1073,         -0x1p+0, INEXACT|UNDERFLOW)
T(RD,              -0x1p-1024,-0x1.0000000000004p-1024,         -0x1p+0, INEXACT|UNDERFLOW)
T(RD,              -0x1p-1023,-0x1.0000000000002p-1023,         -0x1p+0, INEXACT|UNDERFLOW)
T(RD,-0x1.ffffffffffffcp-1023,-0x1.ffffffffffffep-1023,         -0x1p+0, INEXACT|UNDERFLOW)
T(RD,-0x1.ffffffffffffep-1023,              -0x1p-1022,         -0x1p+0, INEXACT|UNDERFLOW)
T(RN, 0x1.0000000000001p-1022, 0x1.0000000000001p-1022,          0x0p+0, INEXACT)
T(RN, 0x1.0000000000002p-1022, 0x1.0000000000002p-1022,          0x0p+0, INEXACT)
T(RN, 0x1.ffffffffffffbp-1022, 0x1.ffffffffffffbp-1022,          0x0p+0, INEXACT)
T(RN,               0x1p-1021,               0x1p-1021,          0x0p+0, INEXACT)
T(RN, 0x1.0000000000003p-1021, 0x1.0000000000003p-1021,          0x0p+0, INEXACT)
T(RN,               0x1p-1020,               0x1p-1020,          0x0p+0, INEXACT)
T(RN,               0x1.8p-27,               0x1.8p-27,       -0x1.2p-2, INEXACT)
T(RN,                 0x1p-26,                 0x1p-26,  -0x1.555556p-2, INEXACT)
T(RN,-0x1.0000000000001p-1022,-0x1.0000000000001p-1022,          0x0p+0, INEXACT)
T(RN,-0x1.0000000000002p-1022,-0x1.0000000000002p-1022,          0x0p+0, INEXACT)
T(RN,-0x1.ffffffffffffbp-1022,-0x1.ffffffffffffbp-1022,          0x0p+0, INEXACT)
T(RN,              -0x1p-1021,              -0x1p-1021,          0x0p+0, INEXACT)
T(RN,-0x1.0000000000003p-1021,-0x1.0000000000003p-1021,          0x0p+0, INEXACT)
T(RN,              -0x1p-1020,              -0x1p-1020,          0x0p+0, INEXACT)
T(RN,              -0x1.8p-27,              -0x1.8p-27,        0x1.2p-2, INEXACT)
T(RN,                -0x1p-26,                -0x1p-26,   0x1.555556p-2, INEXACT)
T(RN,               0x1p-1073,               0x1p-1073,          0x0p+0, INEXACT|UNDERFLOW)
T(RN,             0x1.2p-1071,             0x1.2p-1071,          0x0p+0, INEXACT|UNDERFLOW)
T(RN,               0x1p-1024,               0x1p-1024,          0x0p+0, INEXACT|UNDERFLOW)
T(RN,               0x1p-1023,               0x1p-1023,          0x0p+0, INEXACT|UNDERFLOW)
T(RN, 0x1.ffffffffffffcp-1023, 0x1.ffffffffffffcp-1023,          0x0p+0, INEXACT|UNDERFLOW)
T(RN, 0x1.ffffffffffffep-1023, 0x1.ffffffffffffep-1023,          0x0p+0, INEXACT|UNDERFLOW)
T(RN,              -0x1p-1073,              -0x1p-1073,          0x0p+0, INEXACT|UNDERFLOW)
T(RN,            -0x1.2p-1071,            -0x1.2p-1071,          0x0p+0, INEXACT|UNDERFLOW)
T(RN,              -0x1p-1024,              -0x1p-1024,          0x0p+0, INEXACT|UNDERFLOW)
T(RN,              -0x1p-1023,              -0x1p-1023,          0x0p+0, INEXACT|UNDERFLOW)
T(RN,-0x1.ffffffffffffcp-1023,-0x1.ffffffffffffcp-1023,          0x0p+0, INEXACT|UNDERFLOW)
T(RN,-0x1.ffffffffffffep-1023,-0x1.ffffffffffffep-1023,          0x0p+0, INEXACT|UNDERFLOW)
T(RU,              -0x1p-1022,              -0x1p-1022,          0x0p+0, INEXACT)
T(RU,-0x1.0000000000001p-1022,-0x1.0000000000001p-1022,          0x0p+0, INEXACT)
T(RU,-0x1.0000000000002p-1022,-0x1.0000000000002p-1022,          0x0p+0, INEXACT)
T(RU,-0x1.ffffffffffffbp-1022,-0x1.ffffffffffffbp-1022,          0x0p+0, INEXACT)
T(RU,              -0x1p-1021,              -0x1p-1021,          0x0p+0, INEXACT)
T(RU,-0x1.0000000000003p-1021,-0x1.0000000000003p-1021,          0x0p+0, INEXACT)
T(RU,              -0x1p-1020,              -0x1p-1020,          0x0p+0, INEXACT)
T(RU,              -0x1.8p-27,              -0x1.8p-27,        0x1.2p-2, INEXACT)
T(RU,                -0x1p-26,                -0x1p-26,   0x1.555556p-2, INEXACT)
T(RU,              -0x1p-1074,              -0x1p-1074,          0x0p+0, INEXACT|UNDERFLOW)
T(RU,              -0x1p-1073,              -0x1p-1073,          0x0p+0, INEXACT|UNDERFLOW)
T(RU,            -0x1.2p-1071,            -0x1.2p-1071,          0x0p+0, INEXACT|UNDERFLOW)
T(RU,              -0x1p-1024,              -0x1p-1024,          0x0p+0, INEXACT|UNDERFLOW)
T(RU,              -0x1p-1023,              -0x1p-1023,          0x0p+0, INEXACT|UNDERFLOW)
T(RU,-0x1.ffffffffffffcp-1023,-0x1.ffffffffffffcp-1023,          0x0p+0, INEXACT|UNDERFLOW)
T(RU,-0x1.ffffffffffffep-1023,-0x1.ffffffffffffep-1023,          0x0p+0, INEXACT|UNDERFLOW)
T(RU,                     nan,                     nan,          0x0p+0, 0)
T(RU,                     nan,                     nan,          0x0p+0, 0)
T(RU,                     inf,                     nan,          0x0p+0, INVALID)
T(RU,                    -inf,                     nan,          0x0p+0, INVALID)
T(RU,               0x1p-1022, 0x1.0000000000001p-1022,          0x1p+0, INEXACT)
T(RU, 0x1.0000000000001p-1022, 0x1.0000000000002p-1022,          0x1p+0, INEXACT)
T(RU, 0x1.0000000000002p-1022, 0x1.0000000000003p-1022,          0x1p+0, INEXACT)
T(RU,               0x1p-1021, 0x1.0000000000001p-1021,          0x1p+0, INEXACT)
T(RU,               0x1p-1020, 0x1.0000000000001p-1020,          0x1p+0, INEXACT)
T(RU,               0x1.8p-27,   0x1.8000000000001p-27,        0x1.7p-1, INEXACT)
T(RU,                 0x1p-26,   0x1.0000000000001p-26,   0x1.555556p-1, INEXACT)
T(RU,               0x1p-1074,               0x1p-1073,          0x1p+0, INEXACT|UNDERFLOW)
T(RU,               0x1p-1073,             0x1.8p-1073,          0x1p+0, INEXACT|UNDERFLOW)
T(RU,               0x1p-1024, 0x1.0000000000004p-1024,          0x1p+0, INEXACT|UNDERFLOW)
T(RU,               0x1p-1023, 0x1.0000000000002p-1023,          0x1p+0, INEXACT|UNDERFLOW)
T(RU, 0x1.ffffffffffffcp-1023, 0x1.ffffffffffffep-1023,          0x1p+0, INEXACT|UNDERFLOW)
T(RU, 0x1.ffffffffffffep-1023,               0x1p-1022,          0x1p+0, INEXACT|UNDERFLOW)
T(RZ,               0x1p-1022,               0x1p-1022,          0x0p+0, INEXACT)
T(RZ, 0x1.0000000000001p-1022, 0x1.0000000000001p-1022,          0x0p+0, INEXACT)
T(RZ, 0x1.0000000000002p-1022, 0x1.0000000000002p-1022,          0x0p+0, INEXACT)
T(RZ, 0x1.ffffffffffffbp-1022, 0x1.ffffffffffffbp-1022,          0x0p+0, INEXACT)
T(RZ,               0x1p-1021,               0x1p-1021,          0x0p+0, INEXACT)
T(RZ, 0x1.0000000000003p-1021, 0x1.0000000000003p-1021,          0x0p+0, INEXACT)
T(RZ,               0x1p-1020,               0x1p-1020,          0x0p+0, INEXACT)
T(RZ,               0x1.8p-27,               0x1.8p-27,       -0x1.2p-2, INEXACT)
T(RZ,                 0x1p-26,                 0x1p-26,  -0x1.555556p-2, INEXACT)
T(RZ,              -0x1p-1022,              -0x1p-1022,          0x0p+0, INEXACT)
T(RZ,-0x1.0000000000001p-1022,-0x1.0000000000001p-1022,          0x0p+0, INEXACT)
T(RZ,-0x1.0000000000002p-1022,-0x1.0000000000002p-1022,          0x0p+0, INEXACT)
T(RZ,-0x1.ffffffffffffbp-1022,-0x1.ffffffffffffbp-1022,          0x0p+0, INEXACT)
T(RZ,              -0x1p-1021,              -0x1p-1021,          0x0p+0, INEXACT)
T(RZ,-0x1.0000000000003p-1021,-0x1.0000000000003p-1021,          0x0p+0, INEXACT)
T(RZ,              -0x1p-1020,              -0x1p-1020,          0x0p+0, INEXACT)
T(RZ,              -0x1.8p-27,              -0x1.8p-27,        0x1.2p-2, INEXACT)
T(RZ,                -0x1p-26,                -0x1p-26,   0x1.555556p-2, INEXACT)
T(RZ,               0x1p-1074,               0x1p-1074,          0x0p+0, INEXACT|UNDERFLOW)
T(RZ,               0x1p-1073,               0x1p-1073,          0x0p+0, INEXACT|UNDERFLOW)
T(RZ,             0x1.2p-1071,             0x1.2p-1071,          0x0p+0, INEXACT|UNDERFLOW)
T(RZ,               0x1p-1024,               0x1p-1024,          0x0p+0, INEXACT|UNDERFLOW)
T(RZ,               0x1p-1023,               0x1p-1023,          0x0p+0, INEXACT|UNDERFLOW)
T(RZ, 0x1.ffffffffffffcp-1023, 0x1.ffffffffffffcp-1023,          0x0p+0, INEXACT|UNDERFLOW)
T(RZ, 0x1.ffffffffffffep-1023, 0x1.ffffffffffffep-1023,          0x0p+0, INEXACT|UNDERFLOW)
T(RZ,              -0x1p-1074,              -0x1p-1074,          0x0p+0, INEXACT|UNDERFLOW)
T(RZ,              -0x1p-1073,              -0x1p-1073,          0x0p+0, INEXACT|UNDERFLOW)
T(RZ,            -0x1.2p-1071,            -0x1.2p-1071,          0x0p+0, INEXACT|UNDERFLOW)
T(RZ,              -0x1p-1024,              -0x1p-1024,          0x0p+0, INEXACT|UNDERFLOW)
T(RZ,              -0x1p-1023,              -0x1p-1023,          0x0p+0, INEXACT|UNDERFLOW)
T(RZ,-0x1.ffffffffffffcp-1023,-0x1.ffffffffffffcp-1023,          0x0p+0, INEXACT|UNDERFLOW)
T(RZ,-0x1.ffffffffffffep-1023,-0x1.ffffffffffffep-1023,          0x0p+0, INEXACT|UNDERFLOW)
T(RZ,                     nan,                     nan,          0x0p+0, 0)
T(RZ,                     nan,                     nan,          0x0p+0, 0)
T(RZ,                     inf,                     nan,          0x0p+0, INVALID)
T(RZ,                    -inf,                     nan,          0x0p+0, INVALID)
