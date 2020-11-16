// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
import cpp
import semmle.code.cpp.dataflow.DataFlow
import semmle.code.cpp.dataflow.TaintTracking

/**
 * Pointer Expresssion
 */
class PointerExpr extends Expr {
  PointerExpr() {
    getType().getUnderlyingType().getUnspecifiedType() instanceof PointerType or
    this.isConstant()
  }
}

/**
 * Data flow configuration tracking pointer flow from expressions or parameters of pointer type
 * to their accesses.
 */
class PointerConfig extends DataFlow::Configuration {
  PointerConfig() { this = "PointerConfig" }

  override predicate isSource(DataFlow::Node n) {
    hasPointerType(n) and
    // restrict to non-null values, as these are safe to repeatedly free
    not n.asExpr() instanceof NullValue
  }

  override predicate isSink(DataFlow::Node n) {
    hasPointerType(n) and
    n.asExpr() instanceof VariableAccess
  }
}

/**
 * Holds if the data flow node `n` is an expression or parameter of pointer type.
 */
predicate hasPointerType(DataFlow::Node n) {
  n.asExpr().getFullyConverted() instanceof PointerExpr or
  n.asParameter().getType().getUnderlyingType().getUnspecifiedType() instanceof PointerType
}
