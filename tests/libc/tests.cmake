# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE)
string(TOUPPER ${CMAKE_C_COMPILER_ID} MY_COMPILER)
set(BUILD "${MY_COMPILER}:${BUILD_TYPE}")
message("Build for libc tests set to: ${BUILD}")
set(MUSL_PATH "3rdparty//musl//libc-test//src")
set(MUSL_FUNC_PATH "${MUSL_PATH}//functional")
set(MUSL_MATH_PATH "${MUSL_PATH}//math")
set(MUSL_MUSL_PATH "${MUSL_PATH}//musl")
set(MUSL_REGR_PATH "${MUSL_PATH}//regression")

##==============================================================================
##
## Supported tests:
##
##==============================================================================

# Include tests that work on all builds:
set(LIBC_TESTS
    ${MUSL_FUNC_PATH}//argv.c
	${MUSL_MATH_PATH}//asinhl.c
	${MUSL_MATH_PATH}//asinl.c
	${MUSL_MATH_PATH}//atan2l.c
	${MUSL_MATH_PATH}//atanhl.c
	${MUSL_MATH_PATH}//atanl.c
    ${MUSL_FUNC_PATH}//basename.c
	${MUSL_MATH_PATH}//ceill.c
    ${MUSL_FUNC_PATH}//clock_gettime.c
    ${MUSL_FUNC_PATH}//dirname.c
    ${MUSL_FUNC_PATH}//env.c
	${MUSL_MATH_PATH}//erfcl.c
	${MUSL_MATH_PATH}//erfl.c
	${MUSL_MATH_PATH}//exp2l.c
	${MUSL_MATH_PATH}//expl.c
	${MUSL_MATH_PATH}//fmodl.c
	${MUSL_MATH_PATH}//hypotl.c
	${MUSL_MATH_PATH}//ldexpl.c
    ${MUSL_FUNC_PATH}//qsort.c
    ${MUSL_FUNC_PATH}//search_insque.c
    ${MUSL_FUNC_PATH}//search_lsearch.c
    ${MUSL_FUNC_PATH}//search_tsearch.c
    ${MUSL_FUNC_PATH}//snprintf.c
    ${MUSL_FUNC_PATH}//sscanf.c
    ${MUSL_FUNC_PATH}//string.c
    ${MUSL_FUNC_PATH}//string_memcpy.c
    ${MUSL_FUNC_PATH}//string_memmem.c
    ${MUSL_FUNC_PATH}//string_memset.c
    ${MUSL_FUNC_PATH}//string_strchr.c
    ${MUSL_FUNC_PATH}//string_strcspn.c
    ${MUSL_FUNC_PATH}//string_strstr.c
    ${MUSL_FUNC_PATH}//strtod_long.c
    ${MUSL_FUNC_PATH}//strtol.c
    ${MUSL_FUNC_PATH}//strtold.c
    ${MUSL_FUNC_PATH}//udiv.c
    ${MUSL_FUNC_PATH}//wcsstr.c
    ${MUSL_FUNC_PATH}//wcstol.c
    ${MUSL_MATH_PATH}//coshl.c
    ${MUSL_MATH_PATH}//cosl.c
    ${MUSL_MATH_PATH}//expm1l.c	
    ${MUSL_MATH_PATH}//fabsl.c
    ${MUSL_MATH_PATH}//fmaxl.c
    ${MUSL_MATH_PATH}//fminl.c
    ${MUSL_MATH_PATH}//fpclassify.c
	${MUSL_MATH_PATH}//floorl.c
    ${MUSL_MATH_PATH}//frexp.c
    ${MUSL_MATH_PATH}//frexpf.c
    ${MUSL_MATH_PATH}//frexpl.c
    ${MUSL_MATH_PATH}//lgammal.c
    ${MUSL_MATH_PATH}//lgammal_r.c
    ${MUSL_MATH_PATH}//modf.c
    ${MUSL_MATH_PATH}//modff.c
    ${MUSL_MATH_PATH}//modfl.c   
    ${MUSL_MATH_PATH}//remainderl.c
    ${MUSL_MATH_PATH}//remquol.c
    ${MUSL_MATH_PATH}//rintl.c
    ${MUSL_MATH_PATH}//roundl.c
    
)

# Exclude tests that fail on Windows:
if (NOT USE_CLANGW)
    list(APPEND LIBC_TESTS 
        #${MUSL_FUNC_PATH}//sscanf_long.c - running out of memory on Linux
	    ${MUSL_FUNC_PATH}//strtod.c
	    ${MUSL_FUNC_PATH}//strtod_simple.c
        ${MUSL_FUNC_PATH}//strtof.c
        ${MUSL_MATH_PATH}//asin.c
        ${MUSL_MATH_PATH}//acos.c
        ${MUSL_MATH_PATH}//asinf.c
	    ${MUSL_MATH_PATH}//asinhf.c   
	    ${MUSL_MATH_PATH}//atan.c
		${MUSL_MATH_PATH}//atanf.c
		${MUSL_MATH_PATH}//atanh.c
		${MUSL_MATH_PATH}//atanhf.c
		${MUSL_MATH_PATH}//cbrt.c
		${MUSL_MATH_PATH}//cbrtf.c
		${MUSL_MATH_PATH}//cbrtl.c
		${MUSL_MATH_PATH}//ceil.c
		${MUSL_MATH_PATH}//ceilf.c
		${MUSL_MATH_PATH}//copysign.c
		${MUSL_MATH_PATH}//copysignf.c
		${MUSL_MATH_PATH}//copysignl.c
		${MUSL_MATH_PATH}//cos.c
		${MUSL_MATH_PATH}//cosf.c
		${MUSL_MATH_PATH}//cosh.c
		${MUSL_MATH_PATH}//coshf.c	
		${MUSL_MATH_PATH}//drem.c
		${MUSL_MATH_PATH}//dremf.c
		${MUSL_MATH_PATH}//erf.c
		${MUSL_MATH_PATH}//erfc.c
		${MUSL_MATH_PATH}//erfcf.c
		${MUSL_MATH_PATH}//erff.c
		${MUSL_MATH_PATH}//exp10.c
		${MUSL_MATH_PATH}//exp10f.c
		${MUSL_MATH_PATH}//exp10l.c
		${MUSL_MATH_PATH}//exp2.c
		${MUSL_MATH_PATH}//exp2f.c
		${MUSL_MATH_PATH}//exp.c
	    ${MUSL_MATH_PATH}//expf.c
	    ${MUSL_MATH_PATH}//expm1.c
	    ${MUSL_MATH_PATH}//expm1f.c
		${MUSL_MATH_PATH}//fabs.c
		${MUSL_MATH_PATH}//fabsf.c
		${MUSL_MATH_PATH}//fenv.c
		${MUSL_MATH_PATH}//floor.c
		${MUSL_MATH_PATH}//floorf.c
		${MUSL_MATH_PATH}//fma.c
		${MUSL_MATH_PATH}//fmod.c
		${MUSL_MATH_PATH}//fmodf.c
		${MUSL_MATH_PATH}//hypot.c
		${MUSL_MATH_PATH}//hypotf.c
		${MUSL_MATH_PATH}//isless.c
		${MUSL_MATH_PATH}//j0f.c
		${MUSL_MATH_PATH}//j1.c
		${MUSL_MATH_PATH}//j1f.c
		${MUSL_MATH_PATH}//ldexp.c
		${MUSL_MATH_PATH}//ldexpf.c
		${MUSL_MATH_PATH}//llrint.c
		${MUSL_MATH_PATH}//llrintf.c
		${MUSL_MATH_PATH}//llrintl.c
		${MUSL_MATH_PATH}//llround.c
		${MUSL_MATH_PATH}//llroundf.c
		${MUSL_MATH_PATH}//llroundl.c
		${MUSL_MATH_PATH}//log10.c
		${MUSL_MATH_PATH}//log10f.c
		${MUSL_MATH_PATH}//log10l.c
		${MUSL_MATH_PATH}//log1pl.c
		${MUSL_MATH_PATH}//log2.c
		${MUSL_MATH_PATH}//log2f.c
		${MUSL_MATH_PATH}//log2l.c
		${MUSL_MATH_PATH}//logb.c
		${MUSL_MATH_PATH}//logbf.c
		${MUSL_MATH_PATH}//logbl.c
		${MUSL_MATH_PATH}//log.c
		${MUSL_MATH_PATH}//logf.c
		${MUSL_MATH_PATH}//logl.c
		${MUSL_MATH_PATH}//lrint.c
		${MUSL_MATH_PATH}//lrintf.c
		${MUSL_MATH_PATH}//lrintl.c
		${MUSL_MATH_PATH}//lround.c
		${MUSL_MATH_PATH}//lroundf.c
		${MUSL_MATH_PATH}//lroundl.c
        ${MUSL_MATH_PATH}//nearbyint.c
        ${MUSL_MATH_PATH}//nearbyintf.c
        ${MUSL_MATH_PATH}//nearbyintl.c
        ${MUSL_MATH_PATH}//nextafter.c
        ${MUSL_MATH_PATH}//nextafterf.c
        ${MUSL_MATH_PATH}//nextafterl.c
        ${MUSL_MATH_PATH}//nexttoward.c
        ${MUSL_MATH_PATH}//nexttowardf.c
        ${MUSL_MATH_PATH}//nexttowardl.c
        ${MUSL_MATH_PATH}//pow10.c
        ${MUSL_MATH_PATH}//pow10f.c
        ${MUSL_MATH_PATH}//pow10l.c
	${MUSL_MATH_PATH}//remainder.c
    ${MUSL_MATH_PATH}//remainderf.c
    ${MUSL_MATH_PATH}//remquo.c
    ${MUSL_MATH_PATH}//remquof.c
    ${MUSL_MATH_PATH}//rint.c
	${MUSL_MATH_PATH}//rintf.c
    ${MUSL_MATH_PATH}//round.c
    ${MUSL_MATH_PATH}//roundf.c
	
		
    ${MUSL_MATH_PATH}//scalb.c
    ${MUSL_MATH_PATH}//scalbf.c
    ${MUSL_MATH_PATH}//scalbln.c
    ${MUSL_MATH_PATH}//scalblnf.c
    ${MUSL_MATH_PATH}//scalblnl.c
    ${MUSL_MATH_PATH}//sin.c
    ${MUSL_MATH_PATH}//sincos.c
    ${MUSL_MATH_PATH}//sincosf.c
    ${MUSL_MATH_PATH}//sincosl.c
    ${MUSL_MATH_PATH}//sinf.c
    ${MUSL_MATH_PATH}//sinhf.c
    ${MUSL_MATH_PATH}//sinl.c
    ${MUSL_MATH_PATH}//sqrt.c
    ${MUSL_MATH_PATH}//sqrtf.c
    ${MUSL_MATH_PATH}//sqrtl.c
    ${MUSL_MATH_PATH}//tan.c
    ${MUSL_MATH_PATH}//tanf.c
    ${MUSL_MATH_PATH}//tanh.c
    ${MUSL_MATH_PATH}//tanhf.c
    ${MUSL_MATH_PATH}//tanhl.c
    ${MUSL_MATH_PATH}//tanl.c
    ${MUSL_MATH_PATH}//tgammal.c
    ${MUSL_MATH_PATH}//trunc.c
    ${MUSL_MATH_PATH}//truncf.c
    ${MUSL_MATH_PATH}//truncl.c
    ${MUSL_REGR_PATH}//fpclassify-invalid-ld80.c
    ${MUSL_REGR_PATH}//iswspace-null.c
    ${MUSL_REGR_PATH}//lrand48-signextend.c
    ${MUSL_REGR_PATH}//malloc-0.c
    ${MUSL_REGR_PATH}//mbsrtowcs-overflow.c
    ${MUSL_REGR_PATH}//memmem-oob.c
    ${MUSL_REGR_PATH}//memmem-oob-read.c
    ${MUSL_REGR_PATH}//printf-1e9-oob.c
    ${MUSL_REGR_PATH}//printf-fmt-g-round.c
    ${MUSL_REGR_PATH}//printf-fmt-g-zeros.c
    ${MUSL_REGR_PATH}//printf-fmt-n.c
    ${MUSL_REGR_PATH}//scanf-bytes-consumed.c
    ${MUSL_REGR_PATH}//scanf-match-literal-eof.c
    ${MUSL_REGR_PATH}//scanf-nullbyte-char.c
    ${MUSL_REGR_PATH}//wcsncpy-read-overflow.c
    ${MUSL_REGR_PATH}//wcsstr-false-negative.c
    ${MUSL_FUNC_PATH}//clocale_mbfuncs.c
    ${MUSL_FUNC_PATH}//iconv_open.c
    ${MUSL_FUNC_PATH}//memstream.c
    ${MUSL_MATH_PATH}//scalbn.c
    ${MUSL_MATH_PATH}//scalbnf.c
    ${MUSL_MATH_PATH}//scalbnl.c
    ${MUSL_MUSL_PATH}//pleval.c
    ${MUSL_REGR_PATH}//fgets-eof.c
    ${MUSL_REGR_PATH}//iconv-roundtrips.c
    ${MUSL_REGR_PATH}//putenv-doublefree.c
    ${MUSL_REGR_PATH}//strverscmp.c
    ${MUSL_FUNC_PATH}//random.c
    ${MUSL_FUNC_PATH}//time.c
    )
endif()

# Exclude tests that fail on Clang:
if (NOT (USE_CLANGW OR MY_COMPILER MATCHES "CLANG"))
    list(APPEND LIBC_TESTS 
	${MUSL_FUNC_PATH}//tgmath.c
        ${MUSL_MATH_PATH}//fmax.c
        ${MUSL_MATH_PATH}//fmaxf.c
        ${MUSL_MATH_PATH}//fmin.c
        ${MUSL_MATH_PATH}//fminf.c
        ${MUSL_MATH_PATH}//ilogb.c
        ${MUSL_MATH_PATH}//ilogbf.c
        ${MUSL_MATH_PATH}//ilogbl.c
        ${MUSL_MATH_PATH}//pow.c
        ${MUSL_MATH_PATH}//powl.c
        ${MUSL_MATH_PATH}//tgammaf.c
        ${MUSL_MATH_PATH}//y1.c
        ${MUSL_MATH_PATH}//y1f.c
        ${MUSL_MATH_PATH}//yn.c        
    )
endif()

# Exclude tests that fail these Clang builds:
if (NOT (USE_CLANGW OR BUILD MATCHES "CLANG:DEBUG" OR BUILD MATCHES "CLANG:RELWITHDEBINFO"))
    list(APPEND LIBC_TESTS 
        #${MUSL_MATH_PATH}//fdim.c
        #${MUSL_MATH_PATH}//fdimf.c
        #${MUSL_MATH_PATH}//fdiml.c
        #${MUSL_MATH_PATH}//fmaf.c
        #${MUSL_MATH_PATH}//log1p.c
        #${MUSL_MATH_PATH}//log1pf.c
        #${MUSL_MATH_PATH}//powf.c
    )
endif()

##==============================================================================
##
## Broken tests:
##
##==============================================================================

if (FALSE)
    list(APPEND LIBC_TESTS 
        #Issue #1090 opened to track broken test
        ${MUSL_FUNC_PATH}//tls_align.c
    )
endif()

##==============================================================================
##
## Unsupported tests:
##
##==============================================================================

if (FALSE)
    list(APPEND LIBC_TESTS 
        3rdparty//musl//libc-test//src//common//runtest.c
        ${MUSL_FUNC_PATH}//crypt.c
        ${MUSL_FUNC_PATH}//dlopen.c
        ${MUSL_FUNC_PATH}//fcntl.c
        ${MUSL_FUNC_PATH}//fdopen.c
        ${MUSL_FUNC_PATH}//fnmatch.c
        ${MUSL_FUNC_PATH}//fscanf.c
        ${MUSL_FUNC_PATH}//fwscanf.c
        ${MUSL_FUNC_PATH}//inet_pton.c
        ${MUSL_FUNC_PATH}//ipc_msg.c
        ${MUSL_FUNC_PATH}//ipc_sem.c
        ${MUSL_FUNC_PATH}//ipc_shm.c
        ${MUSL_FUNC_PATH}//mbc.c
        ${MUSL_FUNC_PATH}//popen.c
        ${MUSL_FUNC_PATH}//pthread_cancel.c
        ${MUSL_FUNC_PATH}//pthread_cancel-points.c
        ${MUSL_FUNC_PATH}//pthread_cond.c
        ${MUSL_FUNC_PATH}//pthread_mutex.c
        ${MUSL_FUNC_PATH}//pthread_robust.c
        ${MUSL_FUNC_PATH}//pthread_tsd.c
        ${MUSL_FUNC_PATH}//search_hsearch.c
        ${MUSL_FUNC_PATH}//sem_init.c
        ${MUSL_FUNC_PATH}//sem_open.c
        ${MUSL_FUNC_PATH}//setjmp.c
        ${MUSL_FUNC_PATH}//socket.c
        ${MUSL_FUNC_PATH}//spawn.c
        ${MUSL_FUNC_PATH}//stat.c
        ${MUSL_FUNC_PATH}//strftime.c
        ${MUSL_FUNC_PATH}//swprintf.c
        ${MUSL_FUNC_PATH}//tls_align_dlopen.c
        ${MUSL_FUNC_PATH}//tls_init.c
        ${MUSL_FUNC_PATH}//tls_init_dlopen.c
        ${MUSL_FUNC_PATH}//tls_local_exec.c
        ${MUSL_FUNC_PATH}//ungetc.c
        ${MUSL_FUNC_PATH}//vfork.c
        ${MUSL_MATH_PATH}//acosh.c
        ${MUSL_MATH_PATH}//asinh.c
        ${MUSL_MATH_PATH}//fmal.c
        ${MUSL_MATH_PATH}//j0.c
        ${MUSL_MATH_PATH}//jn.c
        ${MUSL_MATH_PATH}//jnf.c
        ${MUSL_MATH_PATH}//lgamma.c
        ${MUSL_MATH_PATH}//lgammaf.c
        ${MUSL_MATH_PATH}//lgammaf_r.c
        ${MUSL_MATH_PATH}//lgamma_r.c
        ${MUSL_MATH_PATH}//sinh.c
        ${MUSL_MATH_PATH}//sinhl.c
        ${MUSL_MATH_PATH}//tgamma.c
        ${MUSL_MATH_PATH}//y0.c
        ${MUSL_MATH_PATH}//y0f.c
        ${MUSL_MATH_PATH}//ynf.c
        ${MUSL_REGR_PATH}//daemon-failure.c
        ${MUSL_REGR_PATH}//dn_expand-empty.c
        ${MUSL_REGR_PATH}//dn_expand-ptr-0.c
        ${MUSL_REGR_PATH}//execle-env.c
        ${MUSL_REGR_PATH}//fflush-exit.c
        ${MUSL_REGR_PATH}//fgetwc-buffering.c
        ${MUSL_REGR_PATH}//flockfile-list.c
        ${MUSL_REGR_PATH}//ftello-unflushed-append.c
        ${MUSL_REGR_PATH}//getpwnam_r-crash.c
        ${MUSL_REGR_PATH}//getpwnam_r-errno.c
        ${MUSL_REGR_PATH}//inet_ntop-v4mapped.c
        ${MUSL_REGR_PATH}//inet_pton-empty-last-field.c
        ${MUSL_REGR_PATH}//malloc-brk-fail.c
        ${MUSL_REGR_PATH}//malloc-oom.c
        ${MUSL_REGR_PATH}//mkdtemp-failure.c
        ${MUSL_REGR_PATH}//mkstemp-failure.c
        ${MUSL_REGR_PATH}//pthread_atfork-errno-clobber.c
        ${MUSL_REGR_PATH}//pthread_cancel-sem_wait.c
        ${MUSL_REGR_PATH}//pthread_condattr_setclock.c
        ${MUSL_REGR_PATH}//pthread_cond-smasher.c
        ${MUSL_REGR_PATH}//pthread_cond_wait-cancel_ignored.c
        ${MUSL_REGR_PATH}//pthread_create-oom.c
        ${MUSL_REGR_PATH}//pthread_exit-cancel.c
        ${MUSL_REGR_PATH}//pthread_exit-dtor.c
        ${MUSL_REGR_PATH}//pthread_once-deadlock.c
        ${MUSL_REGR_PATH}//pthread-robust-detach.c
        ${MUSL_REGR_PATH}//pthread_rwlock-ebusy.c
        ${MUSL_REGR_PATH}//raise-race.c
        ${MUSL_REGR_PATH}//regex-backref-0.c
        ${MUSL_REGR_PATH}//regex-bracket-icase.c
        ${MUSL_REGR_PATH}//regexec-nosub.c
        ${MUSL_REGR_PATH}//regex-ere-backref.c
        ${MUSL_REGR_PATH}//regex-escaped-high-byte.c
        ${MUSL_REGR_PATH}//regex-negated-range.c
        ${MUSL_REGR_PATH}//rewind-clear-error.c
        ${MUSL_REGR_PATH}//rlimit-open-files.c
        ${MUSL_REGR_PATH}//setenv-oom.c
        ${MUSL_REGR_PATH}//sigaltstack.c
        ${MUSL_REGR_PATH}//sigprocmask-internal.c
        ${MUSL_REGR_PATH}//sigreturn.c
        ${MUSL_REGR_PATH}//statvfs.c
        ${MUSL_REGR_PATH}//syscall-sign-extend.c
        ${MUSL_REGR_PATH}//tls_get_new-dtv.c
        ${MUSL_REGR_PATH}//uselocale-0.c
    )
endif()
