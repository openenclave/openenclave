// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
/**
 * @name TOCTOU in ECall Aruguments
 * @description Potential time-of-check and time-of-use vulnerablility in the usage of ECall argiment pointer.
 * @kind problem
 * @id ecall-args-toctou
 * @problem.severity error
 * @tags security
 * @precision medium
 */

import cpp
import semmle.code.cpp.Type
import OpenEnclave

from
  UntrustedMemory hostMem, ECallInputParameter inParam, AssignExpr assExp, VariableAccess va,
  StackVariable var, Expr expr, FieldAccess fa
where
  hostMem.isOriginatedFrom(inParam) and
  assExp.getRValue() = hostMem and
  va = assExp.getLValue() and
  var = va.getTarget() and
  useUsePair(var, _, expr) and
  expr.getEnclosingElement() = fa and
  fa.getTarget().getUnderlyingType() instanceof PointerType
select fa, "Host pointer is used directly, Potential TOCTOU vulnerablity"
