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
// atan2d(+-0,+anything but nan) is +-0
T(RN,                  0x0p+0,                  0x0p+0,                  0x0p+0,          0x0p+0, 0)
T(RN,                  0x0p+0,               0x1p-1074,                  0x0p+0,          0x0p+0, 0)
T(RN,                  0x0p+0,               0x1p-1022,                  0x0p+0,          0x0p+0, 0)
T(RN,                  0x0p+0, 0x1.fffffffffffffp+1023,                  0x0p+0,          0x0p+0, 0)
T(RN,                  0x0p+0,                     inf,                  0x0p+0,          0x0p+0, 0)
T(RN,                 -0x0p+0,                  0x0p+0,                 -0x0p+0,          0x0p+0, 0)
T(RN,                 -0x0p+0,               0x1p-1074,                 -0x0p+0,          0x0p+0, 0)
T(RN,                 -0x0p+0,               0x1p-1022,                 -0x0p+0,          0x0p+0, 0)
T(RN,                 -0x0p+0, 0x1.fffffffffffffp+1023,                 -0x0p+0,          0x0p+0, 0)
T(RN,                 -0x0p+0,                     inf,                 -0x0p+0,          0x0p+0, 0)
T(RZ,                  0x0p+0,                  0x0p+0,                  0x0p+0,          0x0p+0, 0)
T(RZ,                  0x0p+0,               0x1p-1074,                  0x0p+0,          0x0p+0, 0)
T(RZ,                  0x0p+0,               0x1p-1022,                  0x0p+0,          0x0p+0, 0)
T(RZ,                  0x0p+0, 0x1.fffffffffffffp+1023,                  0x0p+0,          0x0p+0, 0)
T(RZ,                  0x0p+0,                     inf,                  0x0p+0,          0x0p+0, 0)
T(RZ,                 -0x0p+0,                  0x0p+0,                 -0x0p+0,          0x0p+0, 0)
T(RZ,                 -0x0p+0,               0x1p-1074,                 -0x0p+0,          0x0p+0, 0)
T(RZ,                 -0x0p+0,               0x1p-1022,                 -0x0p+0,          0x0p+0, 0)
T(RZ,                 -0x0p+0, 0x1.fffffffffffffp+1023,                 -0x0p+0,          0x0p+0, 0)
T(RZ,                 -0x0p+0,                     inf,                 -0x0p+0,          0x0p+0, 0)
T(RU,                  0x0p+0,                  0x0p+0,                  0x0p+0,          0x0p+0, 0)
T(RU,                  0x0p+0,               0x1p-1074,                  0x0p+0,          0x0p+0, 0)
T(RU,                  0x0p+0,               0x1p-1022,                  0x0p+0,          0x0p+0, 0)
T(RU,                  0x0p+0, 0x1.fffffffffffffp+1023,                  0x0p+0,          0x0p+0, 0)
T(RU,                  0x0p+0,                     inf,                  0x0p+0,          0x0p+0, 0)
T(RU,                 -0x0p+0,                  0x0p+0,                 -0x0p+0,          0x0p+0, 0)
T(RU,                 -0x0p+0,               0x1p-1074,                 -0x0p+0,          0x0p+0, 0)
T(RU,                 -0x0p+0,               0x1p-1022,                 -0x0p+0,          0x0p+0, 0)
T(RU,                 -0x0p+0, 0x1.fffffffffffffp+1023,                 -0x0p+0,          0x0p+0, 0)
T(RU,                 -0x0p+0,                     inf,                 -0x0p+0,          0x0p+0, 0)
T(RD,                  0x0p+0,                  0x0p+0,                  0x0p+0,          0x0p+0, 0)
T(RD,                  0x0p+0,               0x1p-1074,                  0x0p+0,          0x0p+0, 0)
T(RD,                  0x0p+0,               0x1p-1022,                  0x0p+0,          0x0p+0, 0)
T(RD,                  0x0p+0, 0x1.fffffffffffffp+1023,                  0x0p+0,          0x0p+0, 0)
T(RD,                  0x0p+0,                     inf,                  0x0p+0,          0x0p+0, 0)
T(RD,                 -0x0p+0,                  0x0p+0,                 -0x0p+0,          0x0p+0, 0)
T(RD,                 -0x0p+0,               0x1p-1074,                 -0x0p+0,          0x0p+0, 0)
T(RD,                 -0x0p+0,               0x1p-1022,                 -0x0p+0,          0x0p+0, 0)
T(RD,                 -0x0p+0, 0x1.fffffffffffffp+1023,                 -0x0p+0,          0x0p+0, 0)
T(RD,                 -0x0p+0,                     inf,                 -0x0p+0,          0x0p+0, 0)
// atan2d(+-0,-anything but nan) is +-pi
T(RN,                  0x0p+0,                    -inf,    0x1.921fb54442d18p+1,  -0x1.1a6264p-2, INEXACT)
T(RN,                  0x0p+0,-0x1.fffffffffffffp+1023,    0x1.921fb54442d18p+1,  -0x1.1a6264p-2, INEXACT)
T(RN,                  0x0p+0,              -0x1p-1022,    0x1.921fb54442d18p+1,  -0x1.1a6264p-2, INEXACT)
T(RN,                  0x0p+0,              -0x1p-1074,    0x1.921fb54442d18p+1,  -0x1.1a6264p-2, INEXACT)
T(RN,                  0x0p+0,                 -0x0p+0,    0x1.921fb54442d18p+1,  -0x1.1a6264p-2, INEXACT)
T(RN,                 -0x0p+0,                    -inf,   -0x1.921fb54442d18p+1,   0x1.1a6264p-2, INEXACT)
T(RN,                 -0x0p+0,-0x1.fffffffffffffp+1023,   -0x1.921fb54442d18p+1,   0x1.1a6264p-2, INEXACT)
T(RN,                 -0x0p+0,              -0x1p-1022,   -0x1.921fb54442d18p+1,   0x1.1a6264p-2, INEXACT)
T(RN,                 -0x0p+0,              -0x1p-1074,   -0x1.921fb54442d18p+1,   0x1.1a6264p-2, INEXACT)
T(RN,                 -0x0p+0,                 -0x0p+0,   -0x1.921fb54442d18p+1,   0x1.1a6264p-2, INEXACT)
//  atan2d(+-anything but 0 and nan, 0) is +- pi/2
T(RN,                     inf,                  0x0p+0,    0x1.921fb54442d18p+0,  -0x1.1a6264p-2, INEXACT)
T(RN,                     inf,                 -0x0p+0,    0x1.921fb54442d18p+0,  -0x1.1a6264p-2, INEXACT)
T(RN, 0x1.fffffffffffffp+1023,                  0x0p+0,    0x1.921fb54442d18p+0,  -0x1.1a6264p-2, INEXACT)
T(RN, 0x1.fffffffffffffp+1023,                 -0x0p+0,    0x1.921fb54442d18p+0,  -0x1.1a6264p-2, INEXACT)
T(RN,               0x1p-1022,                  0x0p+0,    0x1.921fb54442d18p+0,  -0x1.1a6264p-2, INEXACT)
T(RN,               0x1p-1022,                 -0x0p+0,    0x1.921fb54442d18p+0,  -0x1.1a6264p-2, INEXACT)
T(RN,               0x1p-1074,                  0x0p+0,    0x1.921fb54442d18p+0,  -0x1.1a6264p-2, INEXACT)
T(RN,               0x1p-1074,                 -0x0p+0,    0x1.921fb54442d18p+0,  -0x1.1a6264p-2, INEXACT)
T(RN,                    -inf,                  0x0p+0,   -0x1.921fb54442d18p+0,   0x1.1a6264p-2, INEXACT)
T(RN,                    -inf,                 -0x0p+0,   -0x1.921fb54442d18p+0,   0x1.1a6264p-2, INEXACT)
T(RN,-0x1.fffffffffffffp+1023,                  0x0p+0,   -0x1.921fb54442d18p+0,   0x1.1a6264p-2, INEXACT)
T(RN,-0x1.fffffffffffffp+1023,                 -0x0p+0,   -0x1.921fb54442d18p+0,   0x1.1a6264p-2, INEXACT)
T(RN,              -0x1p-1074,                  0x0p+0,   -0x1.921fb54442d18p+0,   0x1.1a6264p-2, INEXACT)
T(RN,              -0x1p-1074,                 -0x0p+0,   -0x1.921fb54442d18p+0,   0x1.1a6264p-2, INEXACT)
T(RN,              -0x1p-1022,                  0x0p+0,   -0x1.921fb54442d18p+0,   0x1.1a6264p-2, INEXACT)
T(RN,              -0x1p-1022,                 -0x0p+0,   -0x1.921fb54442d18p+0,   0x1.1a6264p-2, INEXACT)
// atan2d(big,small) :=: +-pi/2
T(RN, 0x1.fffffffffffffp+1023,               0x1p-1022,    0x1.921fb54442d18p+0,  -0x1.1a6264p-2, INEXACT)
T(RN, 0x1.fffffffffffffp+1023,              -0x1p-1022,    0x1.921fb54442d18p+0,  -0x1.1a6264p-2, INEXACT)
T(RN,-0x1.fffffffffffffp+1023,               0x1p-1022,   -0x1.921fb54442d18p+0,   0x1.1a6264p-2, INEXACT)
T(RN,-0x1.fffffffffffffp+1023,              -0x1p-1022,   -0x1.921fb54442d18p+0,   0x1.1a6264p-2, INEXACT)
T(RZ, 0x1.fffffffffffffp+1023,               0x1p-1022,    0x1.921fb54442d18p+0,  -0x1.1a6264p-2, INEXACT)
T(RZ, 0x1.fffffffffffffp+1023,              -0x1p-1022,    0x1.921fb54442d18p+0,  -0x1.1a6264p-2, INEXACT)
T(RZ,-0x1.fffffffffffffp+1023,               0x1p-1022,   -0x1.921fb54442d18p+0,   0x1.1a6264p-2, INEXACT)
T(RZ,-0x1.fffffffffffffp+1023,              -0x1p-1022,   -0x1.921fb54442d18p+0,   0x1.1a6264p-2, INEXACT)
T(RU, 0x1.fffffffffffffp+1023,               0x1p-1022,    0x1.921fb54442d19p+0,   0x1.72cecep-1, INEXACT)
T(RU, 0x1.fffffffffffffp+1023,              -0x1p-1022,    0x1.921fb54442d19p+0,   0x1.72cecep-1, INEXACT)
T(RU,-0x1.fffffffffffffp+1023,               0x1p-1022,   -0x1.921fb54442d18p+0,   0x1.1a6264p-2, INEXACT)
T(RU,-0x1.fffffffffffffp+1023,              -0x1p-1022,   -0x1.921fb54442d18p+0,   0x1.1a6264p-2, INEXACT)
T(RD, 0x1.fffffffffffffp+1023,               0x1p-1022,    0x1.921fb54442d18p+0,  -0x1.1a6264p-2, INEXACT)
T(RD, 0x1.fffffffffffffp+1023,              -0x1p-1022,    0x1.921fb54442d18p+0,  -0x1.1a6264p-2, INEXACT)
T(RD,-0x1.fffffffffffffp+1023,               0x1p-1022,   -0x1.921fb54442d19p+0,  -0x1.72cecep-1, INEXACT)
T(RD,-0x1.fffffffffffffp+1023,              -0x1p-1022,   -0x1.921fb54442d19p+0,  -0x1.72cecep-1, INEXACT)
// atan2d(small,big) = small/big (big>0)
T(RN,               0x1p-1022, 0x1.fffffffffffffp+1023,                  0x0p+0,         -0x0p+0, INEXACT|UNDERFLOW)
T(RN,              -0x1p-1022, 0x1.fffffffffffffp+1023,                 -0x0p+0,          0x0p+0, INEXACT|UNDERFLOW)
T(RN,               0x1p-1022,-0x1.fffffffffffffp+1023,    0x1.921fb54442d18p+1,  -0x1.1a6264p-2, INEXACT)
T(RN,              -0x1p-1022,-0x1.fffffffffffffp+1023,   -0x1.921fb54442d18p+1,   0x1.1a6264p-2, INEXACT)
T(RZ,               0x1p-1022, 0x1.fffffffffffffp+1023,                  0x0p+0,         -0x0p+0, INEXACT|UNDERFLOW)
T(RZ,              -0x1p-1022, 0x1.fffffffffffffp+1023,                 -0x0p+0,          0x0p+0, INEXACT|UNDERFLOW)
T(RZ,               0x1p-1022,-0x1.fffffffffffffp+1023,    0x1.921fb54442d18p+1,  -0x1.1a6264p-2, INEXACT)
T(RZ,              -0x1p-1022,-0x1.fffffffffffffp+1023,   -0x1.921fb54442d18p+1,   0x1.1a6264p-2, INEXACT)
T(RU,               0x1p-1022, 0x1.fffffffffffffp+1023,               0x1p-1074,          0x1p+0, INEXACT|UNDERFLOW)
T(RU,              -0x1p-1022, 0x1.fffffffffffffp+1023,                 -0x0p+0,          0x0p+0, INEXACT|UNDERFLOW)
T(RU,               0x1p-1022,-0x1.fffffffffffffp+1023,    0x1.921fb54442d19p+1,   0x1.72cecep-1, INEXACT)
T(RU,              -0x1p-1022,-0x1.fffffffffffffp+1023,   -0x1.921fb54442d18p+1,   0x1.1a6264p-2, INEXACT)
T(RD,               0x1p-1022, 0x1.fffffffffffffp+1023,                  0x0p+0,         -0x0p+0, INEXACT|UNDERFLOW)
T(RD,              -0x1p-1022, 0x1.fffffffffffffp+1023,              -0x1p-1074,         -0x1p+0, INEXACT|UNDERFLOW)
T(RD,               0x1p-1022,-0x1.fffffffffffffp+1023,    0x1.921fb54442d18p+1,  -0x1.1a6264p-2, INEXACT)
T(RD,              -0x1p-1022,-0x1.fffffffffffffp+1023,   -0x1.921fb54442d19p+1,  -0x1.72cecep-1, INEXACT)
// atan2d(+-x,+x) = +-pi/4 for normal x
T(RN,               0x1p-1022,               0x1p-1022,    0x1.921fb54442d18p-1,  -0x1.1a6264p-2, INEXACT)
T(RN,              -0x1p-1022,               0x1p-1022,   -0x1.921fb54442d18p-1,   0x1.1a6264p-2, INEXACT)
T(RN, 0x1.fffffffffffffp+1023, 0x1.fffffffffffffp+1023,    0x1.921fb54442d18p-1,  -0x1.1a6264p-2, INEXACT)
T(RN,-0x1.fffffffffffffp+1023, 0x1.fffffffffffffp+1023,   -0x1.921fb54442d18p-1,   0x1.1a6264p-2, INEXACT)
// atan2d(+-x,-x) = +-3pi/4 for normal x
T(RN,               0x1p-1022,              -0x1p-1022,    0x1.2d97c7f3321d2p+1,  -0x1.a79394p-3, INEXACT)
T(RN,              -0x1p-1022,              -0x1p-1022,   -0x1.2d97c7f3321d2p+1,   0x1.a79394p-3, INEXACT)
T(RN,                  0x1p+0,                 -0x1p+0,    0x1.2d97c7f3321d2p+1,  -0x1.a79394p-3, INEXACT)
T(RN,                 -0x1p+0,                 -0x1p+0,   -0x1.2d97c7f3321d2p+1,   0x1.a79394p-3, INEXACT)
T(RN, 0x1.fffffffffffffp+1023,-0x1.fffffffffffffp+1023,    0x1.2d97c7f3321d2p+1,  -0x1.a79394p-3, INEXACT)
T(RN,-0x1.fffffffffffffp+1023,-0x1.fffffffffffffp+1023,   -0x1.2d97c7f3321d2p+1,   0x1.a79394p-3, INEXACT)
// random arguments between -2.0 and 2.0
T(RN,   -0x1.13284b2b5006dp-1,    0x1.6ca8dfb825911p+0,    -0x1.716d1fa13dd6p-2,  -0x1.31471ap-3, INEXACT)
T(RN,    0x1.c2ca609de7505p+0,   -0x1.55f11fba96889p+0,    0x1.1c206d50867f1p+1,  -0x1.d982d2p-2, INEXACT)
T(RN,   -0x1.15679e27084ddp-1,   -0x1.41e131b093c41p-4,   -0x1.b6ff43cc0fa03p+0,   0x1.428fe2p-3, INEXACT)
T(RN,    0x1.281b0d18455f5p+0,    0x1.b5ce34a51b239p+0,    0x1.30789aa67a7b1p-1,   0x1.e13b2ap-2, INEXACT)
T(RN,   -0x1.583481079de4dp-2,   -0x1.ea8223103b871p+0,   -0x1.7be5087e43d19p+1,   0x1.a6c422p-2, INEXACT)
T(RN,   -0x1.aae17f24163e5p-1,    0x1.7a9da1468cce9p-4,   -0x1.75db7c098be45p+0,   0x1.e9c708p-2, INEXACT)
T(RN,   -0x1.844fff258fcbdp+0,    0x1.6ca321ace7da1p+0,   -0x1.a237b131b62afp-1,  -0x1.d5b568p-2, INEXACT)
T(RN,   -0x1.fe09befde0ed5p+0,   -0x1.ff6c7e8e5e899p+0,   -0x1.2dc43c18871b1p+1,   0x1.ece6e2p-7, INEXACT)
T(RN,   -0x1.d24c81412d02dp-1,    0x1.29b6828273bd1p+0,   -0x1.5428a1a6caecfp-1,    0x1.9211bp-2, INEXACT)
T(RN,    0x1.25ea7e8b7c6c5p-1,    0x1.f99598e193549p-1,    0x1.0d9c960b4dda9p-1,   -0x1.000c7p-3, INEXACT)
// atan2d involve nan
T(RN,                  0x0p+0,                     nan,                     nan,          0x0p+0, 0)
T(RN,                  0x1p+0,                     nan,                     nan,          0x0p+0, 0)
T(RN,                     nan,               0x1p-1074,                     nan,          0x0p+0, 0)
T(RN,                     nan,-0x1.fffffffffffffp+1023,                     nan,          0x0p+0, 0)
T(RN,                     nan,                     nan,                     nan,          0x0p+0, 0)
T(RN,                     nan,                     nan,                     nan,          0x0p+0, 0)
T(RZ,                  0x0p+0,                     nan,                     nan,          0x0p+0, 0)
T(RZ,                  0x1p+0,                     nan,                     nan,          0x0p+0, 0)
T(RZ,                     nan,               0x1p-1074,                     nan,          0x0p+0, 0)
T(RZ,                     nan,-0x1.fffffffffffffp+1023,                     nan,          0x0p+0, 0)
T(RZ,                     nan,                     nan,                     nan,          0x0p+0, 0)
T(RZ,                     nan,                     nan,                     nan,          0x0p+0, 0)
T(RU,                  0x0p+0,                     nan,                     nan,          0x0p+0, 0)
T(RU,                  0x1p+0,                     nan,                     nan,          0x0p+0, 0)
T(RU,                     nan,               0x1p-1074,                     nan,          0x0p+0, 0)
T(RU,                     nan,-0x1.fffffffffffffp+1023,                     nan,          0x0p+0, 0)
T(RU,                     nan,                     nan,                     nan,          0x0p+0, 0)
T(RU,                     nan,                     nan,                     nan,          0x0p+0, 0)
T(RD,                  0x0p+0,                     nan,                     nan,          0x0p+0, 0)
T(RD,                  0x1p+0,                     nan,                     nan,          0x0p+0, 0)
T(RD,                     nan,               0x1p-1074,                     nan,          0x0p+0, 0)
T(RD,                     nan,-0x1.fffffffffffffp+1023,                     nan,          0x0p+0, 0)
T(RD,                     nan,                     nan,                     nan,          0x0p+0, 0)
T(RD,                     nan,                     nan,                     nan,          0x0p+0, 0)
//  atan2d(+-(anything but inf and nan), +inf) is +-0
T(RN,               0x1p-1074,                     inf,                  0x0p+0,          0x0p+0, 0)
T(RN, 0x1.fffffffffffffp+1023,                     inf,                  0x0p+0,          0x0p+0, 0)
T(RN,              -0x1p-1074,                     inf,                 -0x0p+0,          0x0p+0, 0)
T(RN,-0x1.fffffffffffffp+1023,                     inf,                 -0x0p+0,          0x0p+0, 0)
T(RZ,               0x1p-1074,                     inf,                  0x0p+0,          0x0p+0, 0)
T(RZ, 0x1.fffffffffffffp+1023,                     inf,                  0x0p+0,          0x0p+0, 0)
T(RZ,              -0x1p-1074,                     inf,                 -0x0p+0,          0x0p+0, 0)
T(RZ,-0x1.fffffffffffffp+1023,                     inf,                 -0x0p+0,          0x0p+0, 0)
T(RU,               0x1p-1074,                     inf,                  0x0p+0,          0x0p+0, 0)
T(RU, 0x1.fffffffffffffp+1023,                     inf,                  0x0p+0,          0x0p+0, 0)
T(RU,              -0x1p-1074,                     inf,                 -0x0p+0,          0x0p+0, 0)
T(RU,-0x1.fffffffffffffp+1023,                     inf,                 -0x0p+0,          0x0p+0, 0)
T(RD,               0x1p-1074,                     inf,                  0x0p+0,          0x0p+0, 0)
T(RD, 0x1.fffffffffffffp+1023,                     inf,                  0x0p+0,          0x0p+0, 0)
T(RD,              -0x1p-1074,                     inf,                 -0x0p+0,          0x0p+0, 0)
T(RD,-0x1.fffffffffffffp+1023,                     inf,                 -0x0p+0,          0x0p+0, 0)
//  atan2d(+-(anything but inf and nan), -inf) is +-pi
T(RN,               0x1p-1074,                    -inf,    0x1.921fb54442d18p+1,  -0x1.1a6264p-2, INEXACT)
T(RN, 0x1.fffffffffffffp+1023,                    -inf,    0x1.921fb54442d18p+1,  -0x1.1a6264p-2, INEXACT)
T(RN,              -0x1p-1074,                    -inf,   -0x1.921fb54442d18p+1,   0x1.1a6264p-2, INEXACT)
T(RN,-0x1.fffffffffffffp+1023,                    -inf,   -0x1.921fb54442d18p+1,   0x1.1a6264p-2, INEXACT)
//  atan2d(+-inf,+inf ) is +-pi/4
T(RN,                     inf,                     inf,    0x1.921fb54442d18p-1,  -0x1.1a6264p-2, INEXACT)
T(RN,                    -inf,                     inf,   -0x1.921fb54442d18p-1,   0x1.1a6264p-2, INEXACT)
//  atan2d(+-inf,-inf ) is +-3pi/4
T(RN,                     inf,                    -inf,    0x1.2d97c7f3321d2p+1,  -0x1.a79394p-3, INEXACT)
T(RN,                    -inf,                    -inf,   -0x1.2d97c7f3321d2p+1,   0x1.a79394p-3, INEXACT)
//  atan2d(+-inf, (anything but,0,nan, and inf)) is +-pi/2
T(RN,                     inf,               0x1p-1074,    0x1.921fb54442d18p+0,  -0x1.1a6264p-2, INEXACT)
T(RN,                     inf,              -0x1p-1074,    0x1.921fb54442d18p+0,  -0x1.1a6264p-2, INEXACT)
T(RN,                     inf, 0x1.fffffffffffffp+1023,    0x1.921fb54442d18p+0,  -0x1.1a6264p-2, INEXACT)
T(RN,                     inf,-0x1.fffffffffffffp+1023,    0x1.921fb54442d18p+0,  -0x1.1a6264p-2, INEXACT)
T(RN,                    -inf,               0x1p-1074,   -0x1.921fb54442d18p+0,   0x1.1a6264p-2, INEXACT)
T(RN,                    -inf,              -0x1p-1074,   -0x1.921fb54442d18p+0,   0x1.1a6264p-2, INEXACT)
T(RN,                    -inf, 0x1.fffffffffffffp+1023,   -0x1.921fb54442d18p+0,   0x1.1a6264p-2, INEXACT)
T(RN,                    -inf,-0x1.fffffffffffffp+1023,   -0x1.921fb54442d18p+0,   0x1.1a6264p-2, INEXACT)
