// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
/**
 * @name Double-Free Vulnerability
 * @description Potential Double-Free Vulnerability
 * @kind problem
 * @id doublefree
 * @problem.severity warning
 * @tags security
 * @precision low
 */

import cpp
import semmle.code.cpp.dataflow.DataFlow
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.controlflow.Guards
import UseAfterFree
import Memory
import Exclusions

/**
 * Denotes an access to a non local variable which is never passed to a memset function.
 */
class NonMemsetVariableAccess extends VariableAccess {
  NonMemsetVariableAccess() {
    not getTarget() instanceof LocalVariable and
    not exists(VariableAccess preVa |
      preVa = getAPredecessor().(VariableAccess) and preVa.getTarget() instanceof LocalVariable
    ) and
    not exists(MemsetCall mc |
      (
        this instanceof FieldAccess and
        getAPredecessor().(VariableAccess).getTarget() =
          mc.getDestExpr().(VariableAccess).getTarget()
      )
    )
  }
}

from EffectiveFreeCall freeCall, NonMemsetVariableAccess use, DataFlow::Node source
where
  useAfterFree(source, freeCall, _, use) and
  use = any(EffectiveFreeCall freeCall2).getAFreedArgument() and
  oe_exclude_depends(use.getFile())
select use, "Memory released here but not set to NULL, Potential Double-Free Vulnerability"
