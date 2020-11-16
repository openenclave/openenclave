// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
/**
 * @name Uninitialized argument used in OCall.
 * @description Passing uninitialized argument to an OCall could lead to information disclosure.
 * @kind problem
 * @id ocall-args-infodisco
 * @problem.severity warning
 * @tags security
 * @precision medium
 */

import cpp
import semmle.code.cpp.Type
import semmle.code.cpp.dataflow.DataFlow
import semmle.code.cpp.models.implementations.Strcpy
import Exclusions
import OpenEnclave

from LocalVariable v, VariableAccess va, OCallFunctionCall ofnCall
where
  ofnCall.getNumberOfArguments() > 0 and
  ofnCall.getAnArgumentSubExpr(_) = va and
  v = va.getTarget() and
  oe_exclude_depends(ofnCall.getFile()) and
  not exists(v.getInitializer()) and
  not exists(v.getAnAssignment()) and
  not v.getAnAccess() =
    any(Call c | c.getTarget().getName().matches("%mem%")).getAnArgumentSubExpr(0) and
  DataFlow::localFlowStep(DataFlow::exprNode(v.getAnAccess()), _)
select va, "Uninitialized argument passed to OCall"
