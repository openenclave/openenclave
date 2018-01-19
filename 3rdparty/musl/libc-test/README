libc-test is developed as part of the musl project
http://www.musl-libc.org/

configuring:
	cp config.mak.def config.mak
	edit config.mak
build and run tests:
	make
clean up:
	make clean

make builds all test binaries and runs them to create
a REPORT file that contains all build and runtime errors
(this means that make does not stop at build failures)

contributing tests:

design goals:

- tests should be easy to run and build even a single test in isolation
(so test should be self contained if possible)
- failure of one test should not interfere with others
(build failure, crash or unexpected results are all failures)
- test output should point to the cause of the failure
- test results should be robust
- the test system should have minimal dependency
(libc, posix sh, gnu make)
- the test system should run on all archs and libcs
- tests should leave the system in a clean state

conventions:

each test is in a separate file at a path like src/directory/file.c with
its own main

the test should return 0 on success and non-0 on failure, on failure it
should print error messages to standard out if possible, on success no
message should be printed

to help with the above test protocol use t_error function for printing
errors and return t_status from main, see src/common/test.h
(t_error allows standard printf formatting, outputs at most 512bytes
in a single write call to fd 1, so there is no buffering, long outputs
are truncated, it sets the global t_status to 1)

it is common to do many similar checks in a test, in such cases macros
may be used to simplify the code like
#define T1(a,b) (check(a,b) || (t_error("check(%s,%s) failed\n", a, b),0))
#define T2(f,w) (result=(f), result==(w) || (t_error("%s failed: got %s, want %s\n", #f, result, w),0))

binaries should be possible to run from arbitrary directory.
the build system runs the tests using the src/common/runtest tool which
kills the test process after a timeout and reports the exit status
in case of failure

directories:

src/api: interface tests, build time include header tests
src/common: common utilities compiled into libtest.a
src/functional: functional tests aiming for large coverage of libc
src/math: tests for each math function with input-output test vectors
src/regression: regression tests aiming for testing particular bugs

initial set of functional tests are derived from the libc-testsuit of
Rich Felker, regression tests should contain reference of the bug
(musl commit hash, glibc bug tracker url, etc)

build system:

the main non-file make targets are all, run, clean and cleanall.
(cleanall removes the reports unlike clean, run reruns the dynamically
linked executables)

make variable can be overridden from config.mak or the make command line,
the variable B sets the build directory which is src by default

for each directory under src there are targets like $(B)/directory/all,
$(B)/directory/run and $(B)/directory/clean to make only the contents
of that directory, each directory has its own Makefile set up so it
invokes the top level make with B=src src/directory/foo for the foo
target, so it is possible to work only under a specific test directory

the build and runtime errors of each target are accumulated into a
target.err file and in the end they are concatenated into a REPORT

each .c file in src/functional and src/regression are built into a
dynamic linked and a static linked executable test binary by default,
this behaviour can be changed by a similarly named .mk file changing
make variables and specifying additional rules:

$(B)/$(N) is the name of the binary target (the file name without the .c)
$(B)/$(N)-static is the name of the static binary target
$(B)/$(D) is the build directory
$(N).CFLAGS are added to the CFLAGS at compilation
$(N).LDFLAGS are added to the LDFLAGS at linking
$(N).LDLIBS are added to the LDLIBS at linking
$(N).BINS are the targets (if empty no binaries are built)
$(N).LIBS are the non-executable targets (shared objects may use it)

if a binary is linked together from several .o files then they
have to be specified as prerequisits for the binary targets and
added to the $(N).LDLIBS as well

if a binary depends on a file at runtime (eg. a .so opened by dlopen)
then the $(N).err target should depend on that file
