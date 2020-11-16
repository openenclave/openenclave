// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
import cpp
import semmle.code.cpp.padding.Padding
import Memory

/**
 * A type which contains wasted space on one or more architectures.
 */
class WastedSpaceType extends PaddedType {
  WastedSpaceType() {
    // At least some wasted space
    any(Architecture arch).wastedSpace(this.getUnspecifiedType()) > 0
    or
    exists(Field f |
      f.getDeclaringType() = this and f.getType().getUnspecifiedType() instanceof WastedSpaceType
    )
  }
}

/** A buffer that is potentially leaked. */
abstract class LeakedBuffer extends Expr { }

/** An allocation that potentially escapes the enclosing function. */
class EscapingAllocation extends LeakedBuffer {
  EscapingAllocation() {
    this instanceof Allocation and
    (
      this instanceof StackAllocation
      implies
      exists(VariableAccess va | va = this.(StackAllocation).getAllocationVariable().getAnAccess() |
        // Returned directly
        exists(ReturnStmt ret | ret.getExpr() = va)
      )
    )
    or
    (
      this instanceof Malloc
      implies
      exists(VariableAccess va | va = this.(Malloc).getAnArgumentSubExpr(0) |
        // Returned directly
        exists(ReturnStmt ret | ret.getExpr() = va)
      )
    )
  }
}

/** Holds if there exists some padding between the first and second elements. */
predicate hasInitialPadding(PaddedType pt) {
  exists(Field firstField | pt.(Struct).getAMember(0) = firstField |
    // We want to see if the first non-struct field has alignment padding after it
    if firstField.getType().getUnderlyingType() instanceof Struct
    then
      // First field is a struct, consider padding within this struct
      hasInitialPadding(firstField.getType().getUnspecifiedType())
    else
      /*
       * Look at the second field, and see how much waste there is between the first and second
       * fields.
       */

      exists(Field secondField, Architecture arch |
        not exists(pt.getABaseClass()) and
        /*
         * There is padding between the first two fields if the second fields
         * ends at a larger offset than where it would end if it came right
         * after the first field.
         */

        pt.fieldIndex(secondField) = 2 and
        pt.fieldEnd(2, arch) > pt.fieldEnd(1, arch) + pt.fieldSize(secondField, arch)
      )
  )
}
