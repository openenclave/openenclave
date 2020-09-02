vcvars64.bat x64 && \
mkdir build && \
cd build && \
cmake.exe -G "Ninja" .. && \
ninja.exe && \
ctest.exe
