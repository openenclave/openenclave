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
// acoss(+-1) is 0,pi
T(RN,          0x1p+0,          0x0p+0,          0x0p+0, 0)
T(RN,         -0x1p+0,   0x1.921fb6p+1,   0x1.777a5cp-2, INEXACT)
// acoss(+-(1 - tiny)) :=:  sqrt(2*tiny) or pi-sqrt(2*tiny)
T(RN,   0x1.fffffcp-1,         0x1p-11,  -0x1.555556p-4, INEXACT)
T(RZ,   0x1.fffffcp-1,         0x1p-11,  -0x1.555556p-4, INEXACT)
T(RU,   0x1.fffffcp-1,  0x1.000002p-11,   0x1.d55556p-1, INEXACT)
T(RD,   0x1.fffffcp-1,         0x1p-11,  -0x1.555556p-4, INEXACT)
T(RN,  -0x1.fffffcp-1,   0x1.920fb6p+1,   0x1.777fb2p-2, INEXACT)
T(RZ,  -0x1.fffffcp-1,   0x1.920fb4p+1,  -0x1.444026p-1, INEXACT)
T(RU,  -0x1.fffffcp-1,   0x1.920fb6p+1,   0x1.777fb2p-2, INEXACT)
T(RD,  -0x1.fffffcp-1,   0x1.920fb4p+1,  -0x1.444026p-1, INEXACT)
// acoss(tiny) = pi/2-tiny
T(RN,         0x1p-15,   0x1.921db6p+0,    0x1.777a6p-2, INEXACT)
T(RN,        -0x1p-15,   0x1.9221b6p+0,   0x1.777a5ap-2, INEXACT)
T(RN,         0x1p-29,   0x1.921fb6p+0,   0x1.877a5cp-2, INEXACT)
T(RN,        -0x1p-29,   0x1.921fb6p+0,   0x1.677a5cp-2, INEXACT)
T(RN,        0x1p-126,   0x1.921fb6p+0,   0x1.777a5cp-2, INEXACT)
T(RN,       -0x1p-126,   0x1.921fb6p+0,   0x1.777a5cp-2, INEXACT)
T(RN,          0x0p+0,   0x1.921fb6p+0,   0x1.777a5cp-2, INEXACT)
// some random number between -1 and 1
T(RN,  -0x1.13284cp-2,   0x1.d7c4e6p+0,  -0x1.1d5134p-3, INEXACT)
T(RN,    0x1.6ca8ep-1,   0x1.8e6756p-1,  -0x1.f07dd8p-3, INEXACT)
T(RN,    0x1.c2ca6p-1,   0x1.f9d74cp-2,   0x1.ebd7f8p-3, INEXACT)
T(RN,   -0x1.55f12p-1,   0x1.26abdcp+1,  -0x1.004222p-2, INEXACT)
T(RN,  -0x1.15679ep-2,   0x1.d85a44p+0,  -0x1.c043c2p-2, INEXACT)
T(RN,  -0x1.41e132p-5,   0x1.9c2f68p+0,  -0x1.22d4d4p-2, INEXACT)
T(RN,   0x1.281b0ep-1,    0x1.e881bp-1,  -0x1.71bc6ep-2, INEXACT)
T(RN,   0x1.b5ce34p-1,   0x1.1713f6p-1,  -0x1.4c3306p-2, INEXACT)
T(RN,  -0x1.583482p-3,   0x1.bd5accp+0,   -0x1.0f775p-6, INEXACT)
T(RN,  -0x1.ea8224p-1,   0x1.6ce7d8p+1,   0x1.7f0fbcp-2, INEXACT)
// exception cases
T(RN,   0x1.000002p+0,             nan,          0x0p+0, INVALID)
T(RZ,   0x1.000002p+0,             nan,          0x0p+0, INVALID)
T(RU,   0x1.000002p+0,             nan,          0x0p+0, INVALID)
T(RD,   0x1.000002p+0,             nan,          0x0p+0, INVALID)
T(RN,  -0x1.000002p+0,             nan,          0x0p+0, INVALID)
T(RN,          0x1p+1,             nan,          0x0p+0, INVALID)
T(RN,   0x1.e00002p+2,             nan,          0x0p+0, INVALID)
T(RN,  -0x1.fffffep+2,             nan,          0x0p+0, INVALID)
T(RN,             nan,             nan,          0x0p+0, 0)
T(RN,             nan,             nan,          0x0p+0, 0)
T(RZ,             nan,             nan,          0x0p+0, 0)
T(RU,             nan,             nan,          0x0p+0, 0)
T(RD,             nan,             nan,          0x0p+0, 0)
T(RZ,             nan,             nan,          0x0p+0, 0)
T(RU,             nan,             nan,          0x0p+0, 0)
T(RD,             nan,             nan,          0x0p+0, 0)
T(RD,          0x1p+0,          0x0p+0,          0x0p+0, 0)
T(RD,   0x1.000004p+0,             nan,          0x0p+0, INVALID)
T(RD,          0x1p+1,             nan,          0x0p+0, INVALID)
T(RD,          0x1p+2,             nan,          0x0p+0, INVALID)
T(RD,        0x1p+126,             nan,          0x0p+0, INVALID)
T(RD,        0x1p+127,             nan,          0x0p+0, INVALID)
T(RD, 0x1.fffffcp+127,             nan,          0x0p+0, INVALID)
T(RD, 0x1.fffffep+127,             nan,          0x0p+0, INVALID)
T(RD,             inf,             nan,          0x0p+0, INVALID)
T(RD,  -0x1.000002p+0,             nan,          0x0p+0, INVALID)
T(RD,  -0x1.000004p+0,             nan,          0x0p+0, INVALID)
T(RD,         -0x1p+1,             nan,          0x0p+0, INVALID)
T(RD,         -0x1p+2,             nan,          0x0p+0, INVALID)
T(RD,       -0x1p+126,             nan,          0x0p+0, INVALID)
T(RD,       -0x1p+127,             nan,          0x0p+0, INVALID)
T(RD,-0x1.fffffcp+127,             nan,          0x0p+0, INVALID)
T(RD,-0x1.fffffep+127,             nan,          0x0p+0, INVALID)
T(RD,            -inf,             nan,          0x0p+0, INVALID)
T(RN,   0x1.000004p+0,             nan,          0x0p+0, INVALID)
T(RN,          0x1p+2,             nan,          0x0p+0, INVALID)
T(RN,        0x1p+126,             nan,          0x0p+0, INVALID)
T(RN,        0x1p+127,             nan,          0x0p+0, INVALID)
T(RN, 0x1.fffffcp+127,             nan,          0x0p+0, INVALID)
T(RN, 0x1.fffffep+127,             nan,          0x0p+0, INVALID)
T(RN,             inf,             nan,          0x0p+0, INVALID)
T(RN,  -0x1.000004p+0,             nan,          0x0p+0, INVALID)
T(RN,         -0x1p+1,             nan,          0x0p+0, INVALID)
T(RN,         -0x1p+2,             nan,          0x0p+0, INVALID)
T(RN,       -0x1p+126,             nan,          0x0p+0, INVALID)
T(RN,       -0x1p+127,             nan,          0x0p+0, INVALID)
T(RN,-0x1.fffffcp+127,             nan,          0x0p+0, INVALID)
T(RN,-0x1.fffffep+127,             nan,          0x0p+0, INVALID)
T(RN,            -inf,             nan,          0x0p+0, INVALID)
T(RU,          0x1p+0,          0x0p+0,          0x0p+0, 0)
T(RU,   0x1.000004p+0,             nan,          0x0p+0, INVALID)
T(RU,          0x1p+1,             nan,          0x0p+0, INVALID)
T(RU,          0x1p+2,             nan,          0x0p+0, INVALID)
T(RU,        0x1p+126,             nan,          0x0p+0, INVALID)
T(RU,        0x1p+127,             nan,          0x0p+0, INVALID)
T(RU, 0x1.fffffcp+127,             nan,          0x0p+0, INVALID)
T(RU, 0x1.fffffep+127,             nan,          0x0p+0, INVALID)
T(RU,             inf,             nan,          0x0p+0, INVALID)
T(RU,  -0x1.000002p+0,             nan,          0x0p+0, INVALID)
T(RU,  -0x1.000004p+0,             nan,          0x0p+0, INVALID)
T(RU,         -0x1p+1,             nan,          0x0p+0, INVALID)
T(RU,         -0x1p+2,             nan,          0x0p+0, INVALID)
T(RU,       -0x1p+126,             nan,          0x0p+0, INVALID)
T(RU,       -0x1p+127,             nan,          0x0p+0, INVALID)
T(RU,-0x1.fffffcp+127,             nan,          0x0p+0, INVALID)
T(RU,-0x1.fffffep+127,             nan,          0x0p+0, INVALID)
T(RU,            -inf,             nan,          0x0p+0, INVALID)
T(RU,    0x1.fffffp-1,  0x1.000002p-10,   0x1.555554p-1, INEXACT)
T(RZ,          0x1p+0,          0x0p+0,          0x0p+0, 0)
T(RZ,   0x1.000004p+0,             nan,          0x0p+0, INVALID)
T(RZ,          0x1p+1,             nan,          0x0p+0, INVALID)
T(RZ,          0x1p+2,             nan,          0x0p+0, INVALID)
T(RZ,        0x1p+126,             nan,          0x0p+0, INVALID)
T(RZ,        0x1p+127,             nan,          0x0p+0, INVALID)
T(RZ, 0x1.fffffcp+127,             nan,          0x0p+0, INVALID)
T(RZ, 0x1.fffffep+127,             nan,          0x0p+0, INVALID)
T(RZ,             inf,             nan,          0x0p+0, INVALID)
T(RZ,  -0x1.000002p+0,             nan,          0x0p+0, INVALID)
T(RZ,  -0x1.000004p+0,             nan,          0x0p+0, INVALID)
T(RZ,         -0x1p+1,             nan,          0x0p+0, INVALID)
T(RZ,         -0x1p+2,             nan,          0x0p+0, INVALID)
T(RZ,       -0x1p+126,             nan,          0x0p+0, INVALID)
T(RZ,       -0x1p+127,             nan,          0x0p+0, INVALID)
T(RZ,-0x1.fffffcp+127,             nan,          0x0p+0, INVALID)
T(RZ,-0x1.fffffep+127,             nan,          0x0p+0, INVALID)
T(RZ,            -inf,             nan,          0x0p+0, INVALID)
T(RZ,    0x1.fffffp-1,         0x1p-10,  -0x1.555558p-2, INEXACT)
