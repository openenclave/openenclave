// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
/**
 * @name Possible information leakage from uninitialized padding bytes.
 * @description Uninitialized structure argument with padding bytes passed to OCall
 * @kind problem
 * @id ocall-args-structpadding-infodisco
 * @problem.severity warning
 * @tags security
 * @precision low
 */

import cpp
import semmle.code.cpp.padding.Padding
import Memory
import Padding
import Exclusions

class OCallFunctionCall extends FunctionCall {
  OCallFunctionCall() { this.getTarget().getName().matches("%_ocall") }
}

from Variable v, WastedSpaceType wst, VariableAccess va, OCallFunctionCall ofnCall
where
  ofnCall.getAnArgumentSubExpr(_) = va and
  v = va.getTarget() and
  not exists(v.getInitializer()) and
  hasInitialPadding(wst) and
  // On at least one architecture, there is some wasted space in the form of padding
  v.getType().stripType() = wst and
  // The variable is never the target of a memset/memcpy
  not v.getAnAccess() =
    any(Call c | c.getTarget().getName().matches("%mem%")).getAnArgumentSubExpr(0) and
  // The variable is never freed
  not v.getAnAccess() =
    any(Call c | c.getTarget().getName().matches("%free%")).getAnArgumentSubExpr(0) and
  // Ignore stack variables assigned aggregate literals which zero the allocated memory
  not exists(AggregateLiteral al | v.getAnAssignedValue() = al) and
  oe_exclude_depends(ofnCall.getFile())
select va, "Uninitialized structure argument with padding bytes passed to OCall"
