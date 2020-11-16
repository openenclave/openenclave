// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
import cpp
import semmle.code.cpp.dataflow.DataFlow
import semmle.code.cpp.dataflow.TaintTracking
import PointerDataFlow

/**
 * Denotes a Call to `memset` function
 */
class MemsetCall extends FunctionCall {
  MemsetCall() { getTarget().hasName("memset") }

  Expr getDestExpr() { result = getArgument(0) }

  Expr getSrcExpr() { result = getArgument(1) }

  Expr getSizeExpr() { result = getArgument(2) }
}

/**
 * Denotes a Call to `malloc` function
 */
class Malloc extends HeapAllocation {
  Malloc() { this.getTarget().getName().matches("malloc") }

  override Expr getAllocatedSize() { result = this.getArgument(0) }
}

/**
 * Denotes a Call to `free` function
 */
class FreeCall extends FunctionCall {
  FreeCall() { this.getTarget().getName().matches("free") }

  VariableAccess getFreedVariableAccess() { result = getArgument(0) }
}

/**
 * A call that frees an argument, either directly or
 * by interprocedurally passing it to a free call within the callee.
 */
class EffectiveFreeCall extends FunctionCall {
  Expr freedArg;

  EffectiveFreeCall() {
    freedArg = this.getAnArgument() and
    exists(FreeCall freeCall, VariableAccess freedAccess, PointerConfig config |
      freeCall.getFreedVariableAccess() = freedAccess and
      // the argument of this call flows to the freed variable access
      config.hasFlow(DataFlow::exprNode(freedArg), DataFlow::exprNode(freedAccess)) and
      // but the result of this call does not; this avoids spuriously flagging pass-through functions
      not config.hasFlow(DataFlow::exprNode(this), DataFlow::exprNode(freedAccess))
    )
  }

  Expr getAFreedArgument() { result = freedArg }
}

abstract class Allocation extends Expr { }

/**
 * Denotes an expression which allocates memory on stack.
 */
class StackAllocation extends Allocation {
  StackAllocation() {
    exists(StackVariable var | var.getType().getUnspecifiedType() instanceof Struct |
      var.getInitializer().getExpr() = this
    )
  }

  StackVariable getAllocationVariable() { result.getInitializer().getExpr() = this }
}

/**
 * Denotes an expression which allocates memory on heap.
 */
abstract class HeapAllocation extends Allocation, FunctionCall {
  abstract Expr getAllocatedSize();

  override string toString() { result = FunctionCall.super.toString() }
}
