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
// atan2s(+-0,+anything but nan) is +-0
T(RN,          0x0p+0,          0x0p+0,          0x0p+0,          0x0p+0, 0)
T(RN,          0x0p+0,        0x1p-149,          0x0p+0,          0x0p+0, 0)
T(RN,          0x0p+0,        0x1p-129,          0x0p+0,          0x0p+0, 0)
T(RN,          0x0p+0, 0x1.fffffep+127,          0x0p+0,          0x0p+0, 0)
T(RN,          0x0p+0,             inf,          0x0p+0,          0x0p+0, 0)
T(RN,         -0x0p+0,          0x0p+0,         -0x0p+0,          0x0p+0, 0)
T(RN,         -0x0p+0,        0x1p-149,         -0x0p+0,          0x0p+0, 0)
T(RN,         -0x0p+0,        0x1p-129,         -0x0p+0,          0x0p+0, 0)
T(RN,         -0x0p+0, 0x1.fffffep+127,         -0x0p+0,          0x0p+0, 0)
T(RN,         -0x0p+0,             inf,         -0x0p+0,          0x0p+0, 0)
// atan2s(+-0,-anything but nan) is +-pi
T(RN,          0x0p+0,            -inf,   0x1.921fb6p+1,   0x1.777a5cp-2, INEXACT)
T(RN,          0x0p+0,-0x1.fffffep+127,   0x1.921fb6p+1,   0x1.777a5cp-2, INEXACT)
T(RN,          0x0p+0,       -0x1p-129,   0x1.921fb6p+1,   0x1.777a5cp-2, INEXACT)
T(RN,          0x0p+0,       -0x1p-149,   0x1.921fb6p+1,   0x1.777a5cp-2, INEXACT)
T(RN,          0x0p+0,         -0x0p+0,   0x1.921fb6p+1,   0x1.777a5cp-2, INEXACT)
T(RN,         -0x0p+0,            -inf,  -0x1.921fb6p+1,  -0x1.777a5cp-2, INEXACT)
T(RN,         -0x0p+0,-0x1.fffffep+127,  -0x1.921fb6p+1,  -0x1.777a5cp-2, INEXACT)
T(RN,         -0x0p+0,       -0x1p-129,  -0x1.921fb6p+1,  -0x1.777a5cp-2, INEXACT)
T(RN,         -0x0p+0,       -0x1p-149,  -0x1.921fb6p+1,  -0x1.777a5cp-2, INEXACT)
T(RN,         -0x0p+0,         -0x0p+0,  -0x1.921fb6p+1,  -0x1.777a5cp-2, INEXACT)
//  atan2s(+-anything but 0 and nan, 0) is +- pi/2
T(RN,             inf,          0x0p+0,   0x1.921fb6p+0,   0x1.777a5cp-2, INEXACT)
T(RN,             inf,         -0x0p+0,   0x1.921fb6p+0,   0x1.777a5cp-2, INEXACT)
T(RN, 0x1.fffffep+127,          0x0p+0,   0x1.921fb6p+0,   0x1.777a5cp-2, INEXACT)
T(RN, 0x1.fffffep+127,         -0x0p+0,   0x1.921fb6p+0,   0x1.777a5cp-2, INEXACT)
T(RN,        0x1p-126,          0x0p+0,   0x1.921fb6p+0,   0x1.777a5cp-2, INEXACT)
T(RN,        0x1p-126,         -0x0p+0,   0x1.921fb6p+0,   0x1.777a5cp-2, INEXACT)
T(RN,        0x1p-149,          0x0p+0,   0x1.921fb6p+0,   0x1.777a5cp-2, INEXACT)
T(RN,        0x1p-149,         -0x0p+0,   0x1.921fb6p+0,   0x1.777a5cp-2, INEXACT)
T(RN,            -inf,          0x0p+0,  -0x1.921fb6p+0,  -0x1.777a5cp-2, INEXACT)
T(RN,            -inf,         -0x0p+0,  -0x1.921fb6p+0,  -0x1.777a5cp-2, INEXACT)
T(RN,-0x1.fffffep+127,          0x0p+0,  -0x1.921fb6p+0,  -0x1.777a5cp-2, INEXACT)
T(RN,-0x1.fffffep+127,         -0x0p+0,  -0x1.921fb6p+0,  -0x1.777a5cp-2, INEXACT)
T(RN,       -0x1p-126,          0x0p+0,  -0x1.921fb6p+0,  -0x1.777a5cp-2, INEXACT)
T(RN,       -0x1p-126,         -0x0p+0,  -0x1.921fb6p+0,  -0x1.777a5cp-2, INEXACT)
T(RN,       -0x1p-149,          0x0p+0,  -0x1.921fb6p+0,  -0x1.777a5cp-2, INEXACT)
T(RN,       -0x1p-149,         -0x0p+0,  -0x1.921fb6p+0,  -0x1.777a5cp-2, INEXACT)
// atan2s(big,small) :=: +-pi/2
T(RN, 0x1.fffffep+127,        0x1p-126,   0x1.921fb6p+0,   0x1.777a5cp-2, INEXACT)
T(RN, 0x1.fffffep+127,       -0x1p-126,   0x1.921fb6p+0,   0x1.777a5cp-2, INEXACT)
T(RN,-0x1.fffffep+127,        0x1p-126,  -0x1.921fb6p+0,  -0x1.777a5cp-2, INEXACT)
T(RN,-0x1.fffffep+127,       -0x1p-126,  -0x1.921fb6p+0,  -0x1.777a5cp-2, INEXACT)
T(RZ, 0x1.fffffep+127,        0x1p-126,   0x1.921fb4p+0,  -0x1.4442d2p-1, INEXACT)
T(RZ, 0x1.fffffep+127,       -0x1p-126,   0x1.921fb4p+0,  -0x1.4442d2p-1, INEXACT)
T(RZ,-0x1.fffffep+127,        0x1p-126,  -0x1.921fb4p+0,   0x1.4442d2p-1, INEXACT)
T(RZ,-0x1.fffffep+127,       -0x1p-126,  -0x1.921fb4p+0,   0x1.4442d2p-1, INEXACT)
T(RU, 0x1.fffffep+127,        0x1p-126,   0x1.921fb6p+0,   0x1.777a5cp-2, INEXACT)
T(RU, 0x1.fffffep+127,       -0x1p-126,   0x1.921fb6p+0,   0x1.777a5cp-2, INEXACT)
T(RU,-0x1.fffffep+127,        0x1p-126,  -0x1.921fb4p+0,   0x1.4442d2p-1, INEXACT)
T(RU,-0x1.fffffep+127,       -0x1p-126,  -0x1.921fb4p+0,   0x1.4442d2p-1, INEXACT)
T(RD, 0x1.fffffep+127,        0x1p-126,   0x1.921fb4p+0,  -0x1.4442d2p-1, INEXACT)
T(RD, 0x1.fffffep+127,       -0x1p-126,   0x1.921fb4p+0,  -0x1.4442d2p-1, INEXACT)
T(RD,-0x1.fffffep+127,        0x1p-126,  -0x1.921fb6p+0,  -0x1.777a5cp-2, INEXACT)
T(RD,-0x1.fffffep+127,       -0x1p-126,  -0x1.921fb6p+0,  -0x1.777a5cp-2, INEXACT)
// atan2s(small,big) = small/big (big>0)
T(RN,        0x1p-126, 0x1.fffffep+127,          0x0p+0,-0x1.000002p-105, INEXACT|UNDERFLOW)
T(RN,       -0x1p-126, 0x1.fffffep+127,         -0x0p+0, 0x1.000002p-105, INEXACT|UNDERFLOW)
T(RN,        0x1p-126,-0x1.fffffep+127,   0x1.921fb6p+1,   0x1.777a5cp-2, INEXACT)
T(RN,       -0x1p-126,-0x1.fffffep+127,  -0x1.921fb6p+1,  -0x1.777a5cp-2, INEXACT)
T(RZ,        0x1p-126, 0x1.fffffep+127,          0x0p+0,-0x1.000002p-105, INEXACT|UNDERFLOW)
T(RZ,       -0x1p-126, 0x1.fffffep+127,         -0x0p+0, 0x1.000002p-105, INEXACT|UNDERFLOW)
T(RZ,        0x1p-126,-0x1.fffffep+127,   0x1.921fb4p+1,  -0x1.4442d2p-1, INEXACT)
T(RZ,       -0x1p-126,-0x1.fffffep+127,  -0x1.921fb4p+1,   0x1.4442d2p-1, INEXACT)
T(RU,        0x1p-126, 0x1.fffffep+127,        0x1p-149,          0x1p+0, INEXACT|UNDERFLOW)
T(RU,       -0x1p-126, 0x1.fffffep+127,         -0x0p+0, 0x1.000002p-105, INEXACT|UNDERFLOW)
T(RU,        0x1p-126,-0x1.fffffep+127,   0x1.921fb6p+1,   0x1.777a5cp-2, INEXACT)
T(RU,       -0x1p-126,-0x1.fffffep+127,  -0x1.921fb4p+1,   0x1.4442d2p-1, INEXACT)
T(RD,        0x1p-126, 0x1.fffffep+127,          0x0p+0,-0x1.000002p-105, INEXACT|UNDERFLOW)
T(RD,       -0x1p-126, 0x1.fffffep+127,       -0x1p-149,         -0x1p+0, INEXACT|UNDERFLOW)
T(RD,        0x1p-126,-0x1.fffffep+127,   0x1.921fb4p+1,  -0x1.4442d2p-1, INEXACT)
T(RD,       -0x1p-126,-0x1.fffffep+127,  -0x1.921fb6p+1,  -0x1.777a5cp-2, INEXACT)
// atan2s(+-x,+x) = +-pi/4 for normal x
T(RN,        0x1p-126,        0x1p-126,   0x1.921fb6p-1,   0x1.777a5cp-2, INEXACT)
T(RN,       -0x1p-126,        0x1p-126,  -0x1.921fb6p-1,  -0x1.777a5cp-2, INEXACT)
T(RN, 0x1.fffffep+127, 0x1.fffffep+127,   0x1.921fb6p-1,   0x1.777a5cp-2, INEXACT)
T(RN,-0x1.fffffep+127, 0x1.fffffep+127,  -0x1.921fb6p-1,  -0x1.777a5cp-2, INEXACT)
// atan2s(+-x,-x) = +-3pi/4 for normal x
T(RN,        0x1p-126,       -0x1p-126,   0x1.2d97c8p+1,   0x1.99bc5cp-6, INEXACT)
T(RN,       -0x1p-126,       -0x1p-126,  -0x1.2d97c8p+1,  -0x1.99bc5cp-6, INEXACT)
T(RN,          0x1p+0,         -0x1p+0,   0x1.2d97c8p+1,   0x1.99bc5cp-6, INEXACT)
T(RN,         -0x1p+0,         -0x1p+0,  -0x1.2d97c8p+1,  -0x1.99bc5cp-6, INEXACT)
T(RN, 0x1.fffffep+127,-0x1.fffffep+127,   0x1.2d97c8p+1,   0x1.99bc5cp-6, INEXACT)
T(RN,-0x1.fffffep+127,-0x1.fffffep+127,  -0x1.2d97c8p+1,  -0x1.99bc5cp-6, INEXACT)
// random arguments between -2.0 and 2.0
T(RN,  -0x1.13284cp-1,    0x1.6ca8ep+0,   -0x1.716d2p-2,    0x1.90111p-3, INEXACT)
T(RN,    0x1.c2ca6p+0,   -0x1.55f12p+0,   0x1.1c206ep+1,   0x1.1ac042p-2, INEXACT)
T(RN,  -0x1.15679ep-1,  -0x1.41e132p-4,  -0x1.b6ff44p+0,  -0x1.2ecaf4p-4, INEXACT)
T(RN,   0x1.281b0ep+0,   0x1.b5ce34p+0,   0x1.30789cp-1,   0x1.17e61ap-3, INEXACT)
T(RN,  -0x1.583482p-2,  -0x1.ea8224p+0,  -0x1.7be508p+1,   0x1.e4c608p-3, INEXACT)
T(RN,   -0x1.aae18p-1,   0x1.7a9da2p-4,  -0x1.75db7cp+0,   0x1.483b7cp-6, INEXACT)
T(RN,     -0x1.845p+0,   0x1.6ca322p+0,  -0x1.a237b2p-1,   -0x1.e3262p-3, INEXACT)
T(RN,  -0x1.fe09bep+0,  -0x1.ff6c7ep+0,  -0x1.2dc43cp+1,   0x1.348c12p-4, INEXACT)
T(RN,  -0x1.d24c82p-1,   0x1.29b682p+0,  -0x1.5428a2p-1,   0x1.e59fe4p-3, INEXACT)
T(RN,   0x1.25ea7ep-1,   0x1.f99598p-1,   0x1.0d9c96p-1,  -0x1.3ef8ecp-7, INEXACT)
// atan2s involve nan
T(RN,          0x0p+0,             nan,             nan,          0x0p+0, 0)
T(RN,          0x1p+0,             nan,             nan,          0x0p+0, 0)
T(RN,             nan,        0x1p-149,             nan,          0x0p+0, 0)
T(RN,             nan,-0x1.fffffep+127,             nan,          0x0p+0, 0)
T(RN,             nan,             nan,             nan,          0x0p+0, 0)
T(RN,             nan,             nan,             nan,          0x0p+0, 0)
T(RZ,          0x0p+0,             nan,             nan,          0x0p+0, 0)
T(RZ,          0x1p+0,             nan,             nan,          0x0p+0, 0)
T(RZ,             nan,        0x1p-149,             nan,          0x0p+0, 0)
T(RZ,             nan,-0x1.fffffep+127,             nan,          0x0p+0, 0)
T(RZ,             nan,             nan,             nan,          0x0p+0, 0)
T(RZ,             nan,             nan,             nan,          0x0p+0, 0)
T(RU,          0x0p+0,             nan,             nan,          0x0p+0, 0)
T(RU,          0x1p+0,             nan,             nan,          0x0p+0, 0)
T(RU,             nan,        0x1p-149,             nan,          0x0p+0, 0)
T(RU,             nan,-0x1.fffffep+127,             nan,          0x0p+0, 0)
T(RU,             nan,             nan,             nan,          0x0p+0, 0)
T(RU,             nan,             nan,             nan,          0x0p+0, 0)
T(RD,          0x0p+0,             nan,             nan,          0x0p+0, 0)
T(RD,          0x1p+0,             nan,             nan,          0x0p+0, 0)
T(RD,             nan,        0x1p-149,             nan,          0x0p+0, 0)
T(RD,             nan,-0x1.fffffep+127,             nan,          0x0p+0, 0)
T(RD,             nan,             nan,             nan,          0x0p+0, 0)
T(RD,             nan,             nan,             nan,          0x0p+0, 0)
//  atan2s(+-(anything but inf and nan), +inf) is +-0
T(RN,        0x1p-149,             inf,          0x0p+0,          0x0p+0, 0)
T(RN, 0x1.fffffep+127,             inf,          0x0p+0,          0x0p+0, 0)
T(RN,       -0x1p-149,             inf,         -0x0p+0,          0x0p+0, 0)
T(RN,-0x1.fffffep+127,             inf,         -0x0p+0,          0x0p+0, 0)
//  atan2s(+-(anything but inf and nan), -inf) is +-pi
T(RN,        0x1p-149,            -inf,   0x1.921fb6p+1,   0x1.777a5cp-2, INEXACT)
T(RN, 0x1.fffffep+127,            -inf,   0x1.921fb6p+1,   0x1.777a5cp-2, INEXACT)
T(RN,       -0x1p-149,            -inf,  -0x1.921fb6p+1,  -0x1.777a5cp-2, INEXACT)
T(RN,-0x1.fffffep+127,            -inf,  -0x1.921fb6p+1,  -0x1.777a5cp-2, INEXACT)
//  atan2s(+-inf,+inf ) is +-pi/4
T(RN,             inf,             inf,   0x1.921fb6p-1,   0x1.777a5cp-2, INEXACT)
T(RN,            -inf,             inf,  -0x1.921fb6p-1,  -0x1.777a5cp-2, INEXACT)
//  atan2s(+-inf,-inf ) is +-3pi/4
T(RN,             inf,            -inf,   0x1.2d97c8p+1,   0x1.99bc5cp-6, INEXACT)
T(RN,            -inf,            -inf,  -0x1.2d97c8p+1,  -0x1.99bc5cp-6, INEXACT)
//  atan2s(+-inf, (anything but,0,nan, and inf)) is +-pi/2
T(RN,             inf,        0x1p-149,   0x1.921fb6p+0,   0x1.777a5cp-2, INEXACT)
T(RN,             inf,       -0x1p-149,   0x1.921fb6p+0,   0x1.777a5cp-2, INEXACT)
T(RN,             inf, 0x1.fffffep+127,   0x1.921fb6p+0,   0x1.777a5cp-2, INEXACT)
T(RN,             inf,-0x1.fffffep+127,   0x1.921fb6p+0,   0x1.777a5cp-2, INEXACT)
T(RN,            -inf,        0x1p-149,  -0x1.921fb6p+0,  -0x1.777a5cp-2, INEXACT)
T(RN,            -inf,       -0x1p-149,  -0x1.921fb6p+0,  -0x1.777a5cp-2, INEXACT)
T(RN,            -inf, 0x1.fffffep+127,  -0x1.921fb6p+0,  -0x1.777a5cp-2, INEXACT)
T(RN,            -inf,-0x1.fffffep+127,  -0x1.921fb6p+0,  -0x1.777a5cp-2, INEXACT)
