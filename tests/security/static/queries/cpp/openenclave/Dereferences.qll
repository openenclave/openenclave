// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
/**
 * Provides classes and predicates for identifying expressions that are dereferences of a pointer.
 *
 * This library detects dereferences that occur locally - for example, in a dereferencing
 * expression, or as an argument to a library call such as memcpy - as well as dereferences that
 * occur by passing pointer arguments to calls that ultimately dereference the argument.
 */

import cpp
import semmle.code.cpp.controlflow.Dereferenced

/**
 * A pointer expression `e` that is dereferenced directly by `op`.
 */
predicate localDereference(Expr op, Expr e) {
  e.getActualType().getUnspecifiedType() instanceof PointerType and
  not op = any(SizeofExprOperator sizeof).getAChild*() and
  (
    e = op.(PointerDereferenceExpr).getOperand()
    or
    e = op.(FieldAccess).getQualifier()
    or
    e = op.(Call).getQualifier()
    or
    e = op.(ArrayExpr).getArrayBase()
    or
    e = op.(ArrayExpr).getArrayOffset()
    or
    localDereference(op, any(PointerArithmeticOperation pOp | e = pOp.getAnOperand()))
    or
    localDereference(op, any(ConditionalExpr c | e = c.getThen() or e = c.getElse()))
    or
    exists(int i | op.(Call).getArgument(i) = e | callDereferences(op, i))
  )
}

/**
 * A pointer expression `e` that is dereferenced directly or indirectly by `op`.
 *
 * Indirect dereferences occur when pointer arguments are passed to functions which ultimately
 * dereference the argument (all calls by value to library functions are assumed to dereference
 * their argument).
 */
predicate opDereferences(Expr op, Expr e) {
  not op = any(SizeofExprOperator sizeof).getAChild*() and
  (
    localDereference(op, e)
    or
    exists(Call call, int i |
      call = op and
      not call.passesByReference(i, e) and
      call.getArgument(i) = e
    |
      indirectDereference(call, e)
      or
      not call.getTarget().hasEntryPoint() // library call
    )
  )
  or
  dereferencedByOperation(op, e)
}

predicate indirectDereference(Call call, Expr e) {
  not call = any(SizeofExprOperator sizeof).getAChild*() and
  exists(int i |
    not call.passesByReference(i, e) and
    call.getArgument(i) = e
  |
    exists(Expr paramUse | parameterUsePair(call.getTarget().getParameter(i), paramUse) |
      opDereferences(_, paramUse)
      or
      exists(Expr step | definitionUsePair(_, paramUse, step) and opDereferences(_, step))
    )
  )
}

/**
 * A pointer expression that is dereferenced, directly or indirectly.
 * Indirect dereferences occur when pointer arguments are passed to functions which ultimately
 * dereference the argument.
 */
class Dereference extends Expr {
  Dereference() { opDereferences(_, this) }

  /** Gets the operation that is performing the dereference of this pointer expression. */
  Expr getDereferencingOperation() { opDereferences(result, this) }
}

/**
 * A pointer expression that is dereferenced indirectly within this function.
 */
class IndirectDereference extends Dereference {
  IndirectDereference() { indirectDereference(_, this) }

  override Expr getDereferencingOperation() { indirectDereference(result, this) }
}

/**
 * A pointer expression that is dereferenced directly within this function.
 */
class DirectDereference extends Dereference {
  DirectDereference() { not this instanceof IndirectDereference }
}

/**
 * A pointer expression that is dereferenced directly within this function.
 */
class LocalDereference extends DirectDereference {
  LocalDereference() { localDereference(_, this) }

  override Expr getDereferencingOperation() { localDereference(result, this) }
}
