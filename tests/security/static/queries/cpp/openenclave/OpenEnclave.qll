// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
import cpp
import semmle.code.cpp.Type
import semmle.code.cpp.dataflow.TaintTracking
import Dereferences

/**
 * EnclaveEnterFunction - Entry point function for an enclave.
 * During an ECALL __oe_handle_main() function is called by oe_enter(), which is called by the EENTER instruction.
 * Since oe_enter is implemented in assembly, CodeQL cannot construct call flow graph flowing from host to enclave.
 * __oe_handle_main can be consideredd as enclave entry point function to porform taint analysis on untrusted host pointers.
 */
class EnclaveEnterFunction extends Function {
  EnclaveEnterFunction() { this.getName() = "__oe_handle_main" }

  Parameter getArg1() { result = getParameter(0) }

  Parameter getArg2() { result = getParameter(1) }

  Parameter getCssa() { result = getParameter(3) }

  Parameter getTcs() { result = getParameter(4) }

  Parameter getOutArg1() { result = getParameter(5) }

  Parameter getOutArg2() { result = getParameter(6) }
}

/**
 * ECALL Input parameter carrying untrusted host pointer.
 */
class ECallInputParameter extends Parameter {
  ECallInputParameter() { this = any(EnclaveEnterFunction ecall).getArg2() }
}

/**
 * UntrustedMemory - Tracing data-flow of untrusted memory that origiates from ECallInputParameter
 */
class UntrustedMemory extends Expr {
  UntrustedMemory() { this instanceof Expr }

  predicate isOriginatedFrom(ECallInputParameter par) {
    parameterUsePair(par, this)
    or
    exists(UntrustedMemory hostMem |
      definitionUsePair(_, hostMem, this)
      or
      exists(FunctionCall fc, int pos | fc.getArgument(pos) = hostMem |
        parameterUsePair(fc.getTarget().getParameter(pos), this)
      )
    |
      hostMem.isOriginatedFrom(par)
    )
  }
}

/**
 * Function definition model for oe_is_outside_enclave
 */
class IsOutsideEnclaveFunction extends Function {
  IsOutsideEnclaveFunction() { this.getName() = "oe_is_outside_enclave" }

  Parameter getPointer() { result = getParameter(0) }

  Parameter getSize() { result = getParameter(1) }
}

/**
 * Call to oe_is_outside_enclave function
 */
class IsOutsideEnclaveFunctionCall extends FunctionCall {
  IsOutsideEnclaveFunctionCall() { this.getTarget() instanceof IsOutsideEnclaveFunction }
}

/**
 * Function definition model for an OCall function.
 */
class OCallFunction extends Function {
  OCallFunction() { this.getName().matches("%_ocall") }
}

/**
 * Call to an OCall function
 */
class OCallFunctionCall extends FunctionCall {
  OCallFunctionCall() { this.getTarget() instanceof OCallFunction }
}

/**
 * Structure definition model for _oe_call_enclave_function_args
 */
class OE_call_enclave_function_args_t extends Struct {
  OE_call_enclave_function_args_t() {
    this.(Struct).getName().matches("_oe_call_enclave_function_args")
  }

  Field get_function_id() { result = getCanonicalMember(0) }

  Field get_input_buffer() { result = getCanonicalMember(1) }

  Field get_input_buffer_size() { result = getCanonicalMember(2) }

  Field get_output_buffer() { result = getCanonicalMember(3) }

  Field get_output_buffer_size() { result = getCanonicalMember(4) }

  Field get_output_bytes_written() { result = getCanonicalMember(5) }

  Field get_result() { result = getCanonicalMember(6) }
}
