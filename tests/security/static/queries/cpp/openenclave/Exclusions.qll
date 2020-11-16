// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
import cpp
import semmle.code.cpp.File

predicate oe_exclude_depends(File f) {
  not f.getFile().getAbsolutePath().matches("%/usr/include%") and
  not f.getFile().getAbsolutePath().matches("%3rdparty%") and
  not f.getFile().getAbsolutePath().matches("%/libc%") and
  not f.getFile().getAbsolutePath().matches("%c++%") and
  not f.getFile().getAbsolutePath().matches("%tools%")and
  not f.getFile().getAbsolutePath().matches("%tests/%") 
}
