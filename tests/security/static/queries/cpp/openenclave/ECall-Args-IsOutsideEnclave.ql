// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
/**
 * @name Missing enclave boundary check when accessing untrusted memory.
 * @description When host pointers are passed as arguments to ECall, There has to a check
 *              to validate if the memory region is outside the enclave memory boundary.
 * @kind problem
 * @id ecall-args-isoutsideenclave
 * @problem.severity error
 * @tags security
 * @precision medium
 */

import cpp
import semmle.code.cpp.Type
import semmle.code.cpp.dataflow.TaintTracking
import OpenEnclave

/**
 * IsOutsideEnclaveBarrierGuard - A gaurd condition to check if a basic block is 
 * validated for envalve memory range protection by issuing a call to IsOutsideEnclave.
 */
class IsOutsideEnclaveBarrierGuard extends DataFlow2::BarrierGuard {
  IsOutsideEnclaveBarrierGuard() { this instanceof IsOutsideEnclaveFunctionCall }

  override predicate checks(Expr checked, boolean isTrue) {
    checked = this.(IsOutsideEnclaveFunctionCall).getArgument(0) and
    isTrue = true
  }
}

/**
 * IsOutsideEnclaveBarrierConfig - Data-flow configuration to check if the sink is 
 * protected by IsOutsideEnclave validation.
 */
class IsOutsideEnclaveBarrierConfig extends DataFlow::Configuration {
  IsOutsideEnclaveBarrierConfig() { this = "IsOutsideEnclaveBarrierConfig" }

  override predicate isSource(DataFlow::Node source) {
    not exists(IsOutsideEnclaveFunctionCall fc | fc.getArgument(0) = source.asExpr())
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(AssignExpr assExp |
      assExp.getRValue() = sink.asExpr() and
      assExp.getLValue().getType() instanceof PointerType
    )
  }

  override predicate isBarrierGuard(DataFlow::BarrierGuard bg) {
    bg instanceof IsOutsideEnclaveBarrierGuard
  }
}

from
  UntrustedMemory hostMem, ECallInputParameter inParam,
  IsOutsideEnclaveBarrierConfig isOutsideConfig
where
  hostMem.isOriginatedFrom(inParam) and
  isOutsideConfig.hasFlow(DataFlow::exprNode(hostMem), DataFlow::exprNode(hostMem))
select hostMem, "Missing enclave boundary check when accessing untrusted memory."
