// log10.testdata
//  copyright (C) 2005 Ch. Q. Lauter and V.Lefevre
// This file is part of crlibm and is distributed under the GNU Public Licence
// See file COPYING for details
// The following lines are either comments (beginning with a #)
// or give
//   1/ a rounding mode : RN|RU|RD|RZ (crlibm syntax) or  N|P|M|Z (libmcr syntax)
//   2/ The high and low hexadecimal halves of an input
//   3/ The high and low hexadecimal halves of the expected corresponding output
// Test all positive integer powers of 10 for exponents (to 10) from 0 to 25
// especially in the directed rounding modes
// (testing exponents 0 to 17 should suffice in fact)
T(RN,                  0x1p+0,                  0x0p+0,          0x0p+0, 0)
T(RU,                  0x1p+0,                  0x0p+0,          0x0p+0, 0)
T(RD,                  0x1p+0,                  0x0p+0,          0x0p+0, 0)
T(RZ,                  0x1p+0,                  0x0p+0,          0x0p+0, 0)
T(RN,                0x1.4p+3,                  0x1p+0,          0x0p+0, 0)
T(RU,                0x1.4p+3,                  0x1p+0,          0x0p+0, 0)
T(RD,                0x1.4p+3,                  0x1p+0,          0x0p+0, 0)
T(RZ,                0x1.4p+3,                  0x1p+0,          0x0p+0, 0)
T(RN,                0x1.9p+6,                  0x1p+1,          0x0p+0, 0)
T(RU,                0x1.9p+6,                  0x1p+1,          0x0p+0, 0)
T(RD,                0x1.9p+6,                  0x1p+1,          0x0p+0, 0)
T(RZ,                0x1.9p+6,                  0x1p+1,          0x0p+0, 0)
T(RN,               0x1.f4p+9,                0x1.8p+1,          0x0p+0, 0)
T(RU,               0x1.f4p+9,                0x1.8p+1,          0x0p+0, 0)
T(RD,               0x1.f4p+9,                0x1.8p+1,          0x0p+0, 0)
T(RZ,               0x1.f4p+9,                0x1.8p+1,          0x0p+0, 0)
T(RN,             0x1.388p+13,                  0x1p+2,          0x0p+0, 0)
T(RU,             0x1.388p+13,                  0x1p+2,          0x0p+0, 0)
T(RD,             0x1.388p+13,                  0x1p+2,          0x0p+0, 0)
T(RZ,             0x1.388p+13,                  0x1p+2,          0x0p+0, 0)
T(RN,             0x1.86ap+16,                0x1.4p+2,          0x0p+0, 0)
T(RU,             0x1.86ap+16,                0x1.4p+2,          0x0p+0, 0)
T(RD,             0x1.86ap+16,                0x1.4p+2,          0x0p+0, 0)
T(RZ,             0x1.86ap+16,                0x1.4p+2,          0x0p+0, 0)
T(RN,            0x1.e848p+19,                0x1.8p+2,          0x0p+0, 0)
T(RU,            0x1.e848p+19,                0x1.8p+2,          0x0p+0, 0)
T(RD,            0x1.e848p+19,                0x1.8p+2,          0x0p+0, 0)
T(RZ,            0x1.e848p+19,                0x1.8p+2,          0x0p+0, 0)
T(RN,            0x1.312dp+23,                0x1.cp+2,          0x0p+0, 0)
T(RU,            0x1.312dp+23,                0x1.cp+2,          0x0p+0, 0)
T(RD,            0x1.312dp+23,                0x1.cp+2,          0x0p+0, 0)
T(RZ,            0x1.312dp+23,                0x1.cp+2,          0x0p+0, 0)
T(RN,           0x1.7d784p+26,                  0x1p+3,          0x0p+0, 0)
T(RU,           0x1.7d784p+26,                  0x1p+3,          0x0p+0, 0)
T(RD,           0x1.7d784p+26,                  0x1p+3,          0x0p+0, 0)
T(RZ,           0x1.7d784p+26,                  0x1p+3,          0x0p+0, 0)
T(RN,           0x1.dcd65p+29,                0x1.2p+3,          0x0p+0, 0)
T(RU,           0x1.dcd65p+29,                0x1.2p+3,          0x0p+0, 0)
T(RD,           0x1.dcd65p+29,                0x1.2p+3,          0x0p+0, 0)
T(RZ,           0x1.dcd65p+29,                0x1.2p+3,          0x0p+0, 0)
T(RN,          0x1.2a05f2p+33,                0x1.4p+3,          0x0p+0, 0)
T(RU,          0x1.2a05f2p+33,                0x1.4p+3,          0x0p+0, 0)
T(RD,          0x1.2a05f2p+33,                0x1.4p+3,          0x0p+0, 0)
T(RZ,          0x1.2a05f2p+33,                0x1.4p+3,          0x0p+0, 0)
T(RN,         0x1.74876e8p+36,                0x1.6p+3,          0x0p+0, 0)
T(RU,         0x1.74876e8p+36,                0x1.6p+3,          0x0p+0, 0)
T(RD,         0x1.74876e8p+36,                0x1.6p+3,          0x0p+0, 0)
T(RZ,         0x1.74876e8p+36,                0x1.6p+3,          0x0p+0, 0)
T(RN,         0x1.d1a94a2p+39,                0x1.8p+3,          0x0p+0, 0)
T(RU,         0x1.d1a94a2p+39,                0x1.8p+3,          0x0p+0, 0)
T(RD,         0x1.d1a94a2p+39,                0x1.8p+3,          0x0p+0, 0)
T(RZ,         0x1.d1a94a2p+39,                0x1.8p+3,          0x0p+0, 0)
T(RN,        0x1.2309ce54p+43,                0x1.ap+3,          0x0p+0, 0)
T(RU,        0x1.2309ce54p+43,                0x1.ap+3,          0x0p+0, 0)
T(RD,        0x1.2309ce54p+43,                0x1.ap+3,          0x0p+0, 0)
T(RZ,        0x1.2309ce54p+43,                0x1.ap+3,          0x0p+0, 0)
T(RN,        0x1.6bcc41e9p+46,                0x1.cp+3,          0x0p+0, 0)
T(RU,        0x1.6bcc41e9p+46,                0x1.cp+3,          0x0p+0, 0)
T(RD,        0x1.6bcc41e9p+46,                0x1.cp+3,          0x0p+0, 0)
T(RZ,        0x1.6bcc41e9p+46,                0x1.cp+3,          0x0p+0, 0)
T(RN,       0x1.c6bf52634p+49,                0x1.ep+3,          0x0p+0, 0)
T(RU,       0x1.c6bf52634p+49,                0x1.ep+3,          0x0p+0, 0)
T(RD,       0x1.c6bf52634p+49,                0x1.ep+3,          0x0p+0, 0)
T(RZ,       0x1.c6bf52634p+49,                0x1.ep+3,          0x0p+0, 0)
T(RN,      0x1.1c37937e08p+53,                  0x1p+4,          0x0p+0, 0)
T(RU,      0x1.1c37937e08p+53,                  0x1p+4,          0x0p+0, 0)
T(RD,      0x1.1c37937e08p+53,                  0x1p+4,          0x0p+0, 0)
T(RZ,      0x1.1c37937e08p+53,                  0x1p+4,          0x0p+0, 0)
T(RN,      0x1.6345785d8ap+56,                0x1.1p+4,          0x0p+0, 0)
T(RU,      0x1.6345785d8ap+56,                0x1.1p+4,          0x0p+0, 0)
T(RD,      0x1.6345785d8ap+56,                0x1.1p+4,          0x0p+0, 0)
T(RZ,      0x1.6345785d8ap+56,                0x1.1p+4,          0x0p+0, 0)
T(RN,     0x1.bc16d674ec8p+59,                0x1.2p+4,          0x0p+0, 0)
T(RU,     0x1.bc16d674ec8p+59,                0x1.2p+4,          0x0p+0, 0)
T(RD,     0x1.bc16d674ec8p+59,                0x1.2p+4,          0x0p+0, 0)
T(RZ,     0x1.bc16d674ec8p+59,                0x1.2p+4,          0x0p+0, 0)
T(RN,     0x1.158e460913dp+63,                0x1.3p+4,          0x0p+0, 0)
T(RU,     0x1.158e460913dp+63,                0x1.3p+4,          0x0p+0, 0)
T(RD,     0x1.158e460913dp+63,                0x1.3p+4,          0x0p+0, 0)
T(RZ,     0x1.158e460913dp+63,                0x1.3p+4,          0x0p+0, 0)
T(RN,    0x1.5af1d78b58c4p+66,                0x1.4p+4,          0x0p+0, 0)
T(RU,    0x1.5af1d78b58c4p+66,                0x1.4p+4,          0x0p+0, 0)
T(RD,    0x1.5af1d78b58c4p+66,                0x1.4p+4,          0x0p+0, 0)
T(RZ,    0x1.5af1d78b58c4p+66,                0x1.4p+4,          0x0p+0, 0)
T(RN,    0x1.b1ae4d6e2ef5p+69,                0x1.5p+4,          0x0p+0, 0)
T(RU,    0x1.b1ae4d6e2ef5p+69,                0x1.5p+4,          0x0p+0, 0)
T(RD,    0x1.b1ae4d6e2ef5p+69,                0x1.5p+4,          0x0p+0, 0)
T(RZ,    0x1.b1ae4d6e2ef5p+69,                0x1.5p+4,          0x0p+0, 0)
T(RN,   0x1.0f0cf064dd592p+73,                0x1.6p+4,          0x0p+0, 0)
T(RU,   0x1.0f0cf064dd592p+73,                0x1.6p+4,          0x0p+0, 0)
T(RD,   0x1.0f0cf064dd592p+73,                0x1.6p+4,          0x0p+0, 0)
T(RZ,   0x1.0f0cf064dd592p+73,                0x1.6p+4,          0x0p+0, 0)
T(RN,   0x1.52d02c7e14af6p+76,                0x1.7p+4,   0x1.5004e2p-7, INEXACT)
T(RU,   0x1.52d02c7e14af6p+76,                0x1.7p+4,   0x1.5004e2p-7, INEXACT)
T(RD,   0x1.52d02c7e14af6p+76,    0x1.6ffffffffffffp+4,  -0x1.fabfecp-1, INEXACT)
T(RZ,   0x1.52d02c7e14af6p+76,    0x1.6ffffffffffffp+4,  -0x1.fabfecp-1, INEXACT)
T(RN,   0x1.a784379d99db4p+79,                0x1.8p+4,   0x1.0cd0b6p-9, INEXACT)
T(RU,   0x1.a784379d99db4p+79,                0x1.8p+4,   0x1.0cd0b6p-9, INEXACT)
T(RD,   0x1.a784379d99db4p+79,    0x1.7ffffffffffffp+4,   -0x1.fef33p-1, INEXACT)
T(RZ,   0x1.a784379d99db4p+79,    0x1.7ffffffffffffp+4,   -0x1.fef33p-1, INEXACT)
T(RN,   0x1.08b2a2c280291p+83,                0x1.9p+4,  -0x1.6ae68ep-7, INEXACT)
T(RU,   0x1.08b2a2c280291p+83,    0x1.9000000000001p+4,   0x1.fa5466p-1, INEXACT)
T(RD,   0x1.08b2a2c280291p+83,                0x1.9p+4,  -0x1.6ae68ep-7, INEXACT)
T(RZ,   0x1.08b2a2c280291p+83,                0x1.9p+4,  -0x1.6ae68ep-7, INEXACT)
// The very worst case
T(RN,  0x1.e12d66744ff81p+429,    0x1.02d4f53729e45p+7,          0x1p-1, INEXACT)
T(RU,  0x1.e12d66744ff81p+429,    0x1.02d4f53729e45p+7,          0x1p-1, INEXACT)
T(RD,  0x1.e12d66744ff81p+429,    0x1.02d4f53729e44p+7,         -0x1p-1, INEXACT)
T(RZ,  0x1.e12d66744ff81p+429,    0x1.02d4f53729e44p+7,         -0x1p-1, INEXACT)
T(RN,    0x1.ce41d8fa665fap+4,    0x1.75f49c6ad3badp+0,     -0x1.46p-68, INEXACT)
T(RU,    0x1.ce41d8fa665fap+4,    0x1.75f49c6ad3baep+0,          0x1p+0, INEXACT)
T(RD,    0x1.ce41d8fa665fap+4,    0x1.75f49c6ad3badp+0,     -0x1.46p-68, INEXACT)
T(RZ,    0x1.ce41d8fa665fap+4,    0x1.75f49c6ad3badp+0,     -0x1.46p-68, INEXACT)
// One in five of the very worst cases computed by Lefevre and Muller.
// Rounding these values requires evaluating the function to at least 2^(-100).
// These worst cases have been selected thanks to the filterlists 5 script
// If you want the full list please contact Jean-Michel Muller
T(RN,     0x1.62410eb7b7e1p-1,   -0x1.479681c44dd78p-3,         -0x1p-1, INEXACT) // 6.919025992646670175645340350457e-01
T(RZ,    0x1.2a8e6c238a22ep-1,   -0x1.dfbb24b4d439dp-3,          0x1p+0, INEXACT) // 5.831178468116087199035746380105e-01
T(RN,    0x1.b0cf736f1ae1dp-1,   -0x1.2ae5057cd8c44p-4,          0x1p-1, INEXACT) // 8.453327248693686124525470404478e-01
T(RN,    0x1.89825f74aa6b7p+0,    0x1.7e646f3fab0d1p-3,          0x1p-1, INEXACT) // 1.537145582182729119935515882389e+00
T(RN,    0x1.1705af708c532p+2,    0x1.476724bcf05c3p-1,          0x1p-1, INEXACT) // 4.359722003851219440662134729791e+00
T(RZ,    0x1.8070cd731f577p+2,    0x1.8eab1f62d8e8dp-1,   -0x1.edefp-55, INEXACT) // 6.006884920524831805721532873577e+00
T(RN,     0x1.09732bc3fb6fp+3,    0x1.d67138d8e1fabp-1,          0x1p-1, INEXACT) // 8.295308954980527005318435840309e+00
T(RN,    0x1.819598b70b769p+1,    0x1.ea673c9a0bc62p-2,         -0x1p-1, INEXACT) // 3.012377824189503616736374169705e+00
T(RN,    0x1.96c0b463d632ep+3,    0x1.1aab931fc4a83p+0,          0x1p-1, INEXACT) // 1.271102351664884722026727104094e+01
T(RZ,    0x1.3ba0e5e7c603dp+4,    0x1.4b88ce4490878p+0, -0x1.f0e37cp-53, INEXACT) // 1.972678175484201190670319192577e+01
T(RZ,    0x1.f60165d5bc3e1p+5,    0x1.cc30b915ec8c3p+0,         -0x1p+0, INEXACT) // 6.275068251591415702250742469914e+01
T(RN,    0x1.0214115c6897ep+7,    0x1.0e2c2079f4791p+1,         -0x1p-1, INEXACT) // 1.290391949536969491418858524412e+02
T(RN,    0x1.e5b46cc566c89p+7,    0x1.3152e63907254p+1,         -0x1p-1, INEXACT) // 2.428523923576324534678860800341e+02
T(RN,   0x1.13aedb3538379p+12,    0x1.d27ff5ae16374p+1,         -0x1p-1, INEXACT) // 4.410928517551038567034993320704e+03
T(RZ,   0x1.c8ed39b9d8a37p+12,    0x1.ee9674267e65fp+1,   -0x1.ca0ep-60, INEXACT) // 7.310826593252414568269159644842e+03
T(RZ,   0x1.5e441b86eb0e5p+15,    0x1.29b3f213569e3p+2,   -0x1.322ep-55, INEXACT) // 4.483405376371907914290204644203e+04
T(RN,    0x1.c981659f2ca6p+32,    0x1.3c52df27c62b2p+3,          0x1p-1, INEXACT) // 7.675667871174407958984375000000e+09
T(RN,   0x1.fe67e6c6ceb38p+34,    0x1.511c39d418079p+3,         -0x1p-1, INEXACT) // 3.425275778722970581054687500000e+10
T(RN,   0x1.e16ed4ce49996p+37,    0x1.6d326d60c8089p+3,         -0x1p-1, INEXACT) // 2.584673386971998901367187500000e+11
T(RN,   0x1.3f00f03c41303p+38,    0x1.711c39d418079p+3,         -0x1p-1, INEXACT) // 3.425275778722970581054687500000e+11
T(RN,   0x1.51ed94d282c63p+40,     0x1.852d55dca353p+3,          0x1p-1, INEXACT) // 1.451389932162774169921875000000e+12
T(RN,   0x1.a275c0b3d6b93p+60,    0x1.24674679efeeep+4,          0x1p-1, INEXACT) // 1.884576172422697728000000000000e+18
T(RN,   0x1.acf0197df0564p+90,    0x1.b511d58e9bf6ep+4,         -0x1p-1, INEXACT) // 2.074216355977599705575063552000e+27
T(RN,  0x1.2975c05d77d0cp+115,    0x1.1578173b49d48p+5,          0x1p-1, INEXACT) // 4.826563905133211468089089063282e+34
T(RN,  0x1.691810a4906ebp+153,     0x1.71a7dfb3f259p+5,         -0x1p-1, INEXACT) // 1.610533074958623000119510242602e+46
T(RN,  0x1.758976044bfd1p+157,    0x1.7b680b5de7eb4p+5,         -0x1p-1, INEXACT) // 2.665648800401707910762303594475e+47
T(RZ,  0x1.2822af2487796p+165,    0x1.8ddd97d7481f1p+5,  -0x1.65c54p-57, INEXACT) // 5.410031201858834566460604651708e+49
T(RZ,  0x1.00ecbfe1c7e24p+226,    0x1.10232b5bc1921p+6,  -0x1.34878p-58, INEXACT) // 1.082293591137922845086980219250e+68
T(RZ,  0x1.01db5ea232cccp+265,     0x1.3f1ab6b9840dp+6,   -0x1.6b55p-58, INEXACT) // 5.971558130181310987237296921284e+79
T(RN,  0x1.aa8cce883305bp+313,    0x1.79c6c70a21751p+6,          0x1p-1, INEXACT) // 2.780472798533127667532607272298e+94
T(RN,  0x1.6848181b7571cp+318,    0x1.7f80f69d57adep+6,         -0x1p-1, INEXACT) // 7.515203759795911185316596929209e+95
T(RZ,  0x1.f5b55de961a8ep+541,    0x1.464c8348af949p+7,         -0x1p+0, INEXACT) // 1.410714456596528386795551901832e+163
T(RN,  0x1.4d0f00313488cp+576,    0x1.5b03deaa9abb2p+7,         -0x1p-1, INEXACT) // 3.217793610610951495377196763253e+173
T(RN,  0x1.3e238630d4b3bp+581,    0x1.5dfc50d1ef669p+7,          0x1p-1, INEXACT) // 9.835673600325649497978919582662e+174
T(RZ,  0x1.061d60c2c0093p+803,    0x1.e379845eaa774p+7,   -0x1.838ap-59, INEXACT) // 5.461828085706753538145251018537e+241
T(RZ,  0x1.bd35ae5d5fe52p+952,    0x1.1ed22539bd8d6p+8,    -0x1.e9ap-62, INEXACT) // 6.620343395914844405355705099139e+286
