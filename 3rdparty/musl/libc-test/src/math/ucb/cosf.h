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
// coss(+-max)
// coss(tiny) is ~1.0
T(RN,         0x1p-29,          0x1p+0,         0x1p-36, INEXACT)
T(RN,        -0x1p-29,          0x1p+0,         0x1p-36, INEXACT)
T(RN,        0x1p-126,          0x1p+0,          0x0p+0, INEXACT)
T(RN,       -0x1p-126,          0x1p+0,          0x0p+0, INEXACT)
T(RN,        0x1p-149,          0x1p+0,          0x0p+0, INEXACT)
T(RN,       -0x1p-149,          0x1p+0,          0x0p+0, INEXACT)
// coss(+-0) is 1.0
T(RN,          0x0p+0,          0x1p+0,          0x0p+0, 0)
T(RN,         -0x0p+0,          0x1p+0,          0x0p+0, 0)
T(RZ,          0x0p+0,          0x1p+0,          0x0p+0, 0)
T(RZ,         -0x0p+0,          0x1p+0,          0x0p+0, 0)
T(RU,          0x0p+0,          0x1p+0,          0x0p+0, 0)
T(RU,         -0x0p+0,          0x1p+0,          0x0p+0, 0)
T(RD,          0x0p+0,          0x1p+0,          0x0p+0, 0)
T(RD,         -0x0p+0,          0x1p+0,          0x0p+0, 0)
// coss(nan or inf) is nan
T(RN,             inf,             nan,          0x0p+0, INVALID)
T(RN,            -inf,             nan,          0x0p+0, INVALID)
T(RN,             nan,             nan,          0x0p+0, 0)
T(RN,             nan,             nan,          0x0p+0, 0)
T(RD,        0x1p-149,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RD,        0x1p-148,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RD,        0x1p-128,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RD,        0x1p-127,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RD, 0x1.fffff8p-127,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RD, 0x1.fffffcp-127,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RD,        0x1p-126,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RD, 0x1.000002p-126,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RD, 0x1.000004p-126,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RD,        0x1p-125,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RD,        0x1p-124,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RD,         0x1p-27,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RD,         0x1p-11,   0x1.fffffcp-1, -0x1.555556p-25, INEXACT)
T(RD,         0x1p-10,    0x1.fffffp-1, -0x1.555554p-21, INEXACT)
T(RD,       -0x1p-149,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RD,       -0x1p-148,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RD,     -0x1.2p-146,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RD,       -0x1p-128,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RD,       -0x1p-127,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RD,-0x1.fffff8p-127,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RD,-0x1.fffffcp-127,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RD,       -0x1p-126,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RD,-0x1.000002p-126,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RD,-0x1.000004p-126,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RD,-0x1.fffff6p-126,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RD,       -0x1p-125,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RD,-0x1.000006p-125,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RD,       -0x1p-124,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RD,        -0x1p-27,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RD,        -0x1p-11,   0x1.fffffcp-1, -0x1.555556p-25, INEXACT)
T(RD,        -0x1p-10,    0x1.fffffp-1, -0x1.555554p-21, INEXACT)
T(RD,             nan,             nan,          0x0p+0, 0)
T(RD,             inf,             nan,          0x0p+0, INVALID)
T(RD,             nan,             nan,          0x0p+0, 0)
T(RD,            -inf,             nan,          0x0p+0, INVALID)
T(RD,         0x1p-12,   0x1.fffffep-1,         -0x1p-1, INEXACT)
T(RD,        -0x1p-12,   0x1.fffffep-1,         -0x1p-1, INEXACT)
T(RN,        0x1p-148,          0x1p+0,          0x0p+0, INEXACT)
T(RN,      0x1.2p-146,          0x1p+0,          0x0p+0, INEXACT)
T(RN,        0x1p-128,          0x1p+0,          0x0p+0, INEXACT)
T(RN,        0x1p-127,          0x1p+0,          0x0p+0, INEXACT)
T(RN, 0x1.fffff8p-127,          0x1p+0,          0x0p+0, INEXACT)
T(RN, 0x1.fffffcp-127,          0x1p+0,          0x0p+0, INEXACT)
T(RN, 0x1.000002p-126,          0x1p+0,          0x0p+0, INEXACT)
T(RN, 0x1.000004p-126,          0x1p+0,          0x0p+0, INEXACT)
T(RN, 0x1.fffff6p-126,          0x1p+0,          0x0p+0, INEXACT)
T(RN,        0x1p-125,          0x1p+0,          0x0p+0, INEXACT)
T(RN, 0x1.000006p-125,          0x1p+0,          0x0p+0, INEXACT)
T(RN,        0x1p-124,          0x1p+0,          0x0p+0, INEXACT)
T(RN,         0x1p-27,          0x1p+0,         0x1p-32, INEXACT)
T(RN,         0x1p-12,          0x1p+0,          0x1p-2, INEXACT)
T(RN,         0x1p-11,   0x1.fffffcp-1, -0x1.555556p-25, INEXACT)
T(RN,         0x1p-10,    0x1.fffffp-1, -0x1.555554p-21, INEXACT)
T(RN,       -0x1p-148,          0x1p+0,          0x0p+0, INEXACT)
T(RN,     -0x1.2p-146,          0x1p+0,          0x0p+0, INEXACT)
T(RN,       -0x1p-128,          0x1p+0,          0x0p+0, INEXACT)
T(RN,       -0x1p-127,          0x1p+0,          0x0p+0, INEXACT)
T(RN,-0x1.fffff8p-127,          0x1p+0,          0x0p+0, INEXACT)
T(RN,-0x1.fffffcp-127,          0x1p+0,          0x0p+0, INEXACT)
T(RN,-0x1.000002p-126,          0x1p+0,          0x0p+0, INEXACT)
T(RN,-0x1.000004p-126,          0x1p+0,          0x0p+0, INEXACT)
T(RN,-0x1.fffff6p-126,          0x1p+0,          0x0p+0, INEXACT)
T(RN,       -0x1p-125,          0x1p+0,          0x0p+0, INEXACT)
T(RN,-0x1.000006p-125,          0x1p+0,          0x0p+0, INEXACT)
T(RN,       -0x1p-124,          0x1p+0,          0x0p+0, INEXACT)
T(RN,        -0x1p-27,          0x1p+0,         0x1p-32, INEXACT)
T(RN,        -0x1p-12,          0x1p+0,          0x1p-2, INEXACT)
T(RN,        -0x1p-11,   0x1.fffffcp-1, -0x1.555556p-25, INEXACT)
T(RN,        -0x1p-10,    0x1.fffffp-1, -0x1.555554p-21, INEXACT)
T(RU,        0x1p-149,          0x1p+0,          0x0p+0, INEXACT)
T(RU,        0x1p-148,          0x1p+0,          0x0p+0, INEXACT)
T(RU,      0x1.2p-146,          0x1p+0,          0x0p+0, INEXACT)
T(RU,        0x1p-128,          0x1p+0,          0x0p+0, INEXACT)
T(RU,        0x1p-127,          0x1p+0,          0x0p+0, INEXACT)
T(RU, 0x1.fffff8p-127,          0x1p+0,          0x0p+0, INEXACT)
T(RU, 0x1.fffffcp-127,          0x1p+0,          0x0p+0, INEXACT)
T(RU,        0x1p-126,          0x1p+0,          0x0p+0, INEXACT)
T(RU, 0x1.000002p-126,          0x1p+0,          0x0p+0, INEXACT)
T(RU, 0x1.000004p-126,          0x1p+0,          0x0p+0, INEXACT)
T(RU, 0x1.fffff6p-126,          0x1p+0,          0x0p+0, INEXACT)
T(RU,        0x1p-125,          0x1p+0,          0x0p+0, INEXACT)
T(RU, 0x1.000006p-125,          0x1p+0,          0x0p+0, INEXACT)
T(RU,        0x1p-124,          0x1p+0,          0x0p+0, INEXACT)
T(RU,         0x1p-27,          0x1p+0,         0x1p-32, INEXACT)
T(RU,         0x1p-12,          0x1p+0,          0x1p-2, INEXACT)
T(RU,       -0x1p-149,          0x1p+0,          0x0p+0, INEXACT)
T(RU,       -0x1p-148,          0x1p+0,          0x0p+0, INEXACT)
T(RU,       -0x1p-128,          0x1p+0,          0x0p+0, INEXACT)
T(RU,       -0x1p-127,          0x1p+0,          0x0p+0, INEXACT)
T(RU,-0x1.fffff8p-127,          0x1p+0,          0x0p+0, INEXACT)
T(RU,-0x1.fffffcp-127,          0x1p+0,          0x0p+0, INEXACT)
T(RU,       -0x1p-126,          0x1p+0,          0x0p+0, INEXACT)
T(RU,-0x1.000002p-126,          0x1p+0,          0x0p+0, INEXACT)
T(RU,-0x1.000004p-126,          0x1p+0,          0x0p+0, INEXACT)
T(RU,       -0x1p-125,          0x1p+0,          0x0p+0, INEXACT)
T(RU,       -0x1p-124,          0x1p+0,          0x0p+0, INEXACT)
T(RU,        -0x1p-27,          0x1p+0,         0x1p-32, INEXACT)
T(RU,        -0x1p-12,          0x1p+0,          0x1p-2, INEXACT)
T(RU,             nan,             nan,          0x0p+0, 0)
T(RU,             nan,             nan,          0x0p+0, 0)
T(RU,             inf,             nan,          0x0p+0, INVALID)
T(RU,            -inf,             nan,          0x0p+0, INVALID)
T(RU,         0x1p-11,   0x1.fffffep-1,   0x1.fffffep-1, INEXACT)
T(RU,         0x1p-10,   0x1.fffff2p-1,   0x1.ffffeap-1, INEXACT)
T(RU,        -0x1p-11,   0x1.fffffep-1,   0x1.fffffep-1, INEXACT)
T(RU,        -0x1p-10,   0x1.fffff2p-1,   0x1.ffffeap-1, INEXACT)
T(RZ,        0x1p-149,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RZ,        0x1p-148,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RZ,        0x1p-128,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RZ,        0x1p-127,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RZ, 0x1.fffff8p-127,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RZ, 0x1.fffffcp-127,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RZ,        0x1p-126,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RZ, 0x1.000002p-126,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RZ, 0x1.000004p-126,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RZ,        0x1p-125,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RZ,        0x1p-124,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RZ,         0x1p-27,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RZ,         0x1p-11,   0x1.fffffcp-1, -0x1.555556p-25, INEXACT)
T(RZ,         0x1p-10,    0x1.fffffp-1, -0x1.555554p-21, INEXACT)
T(RZ,       -0x1p-149,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RZ,       -0x1p-148,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RZ,       -0x1p-128,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RZ,       -0x1p-127,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RZ,-0x1.fffff8p-127,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RZ,-0x1.fffffcp-127,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RZ,       -0x1p-126,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RZ,-0x1.000002p-126,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RZ,-0x1.000004p-126,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RZ,       -0x1p-125,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RZ,       -0x1p-124,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RZ,        -0x1p-27,   0x1.fffffep-1,         -0x1p+0, INEXACT)
T(RZ,        -0x1p-11,   0x1.fffffcp-1, -0x1.555556p-25, INEXACT)
T(RZ,        -0x1p-10,    0x1.fffffp-1, -0x1.555554p-21, INEXACT)
T(RZ,             nan,             nan,          0x0p+0, 0)
T(RZ,             nan,             nan,          0x0p+0, 0)
T(RZ,             inf,             nan,          0x0p+0, INVALID)
T(RZ,            -inf,             nan,          0x0p+0, INVALID)
T(RZ,         0x1p-12,   0x1.fffffep-1,         -0x1p-1, INEXACT)
T(RZ,        -0x1p-12,   0x1.fffffep-1,         -0x1p-1, INEXACT)
