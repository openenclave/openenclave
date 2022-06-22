SGX Enclave Thread State
-------------------------------

# State Machine
```
            NULL
             |
             v
   -----> ENTERED
  | direct |   |
  | return |   v        AEX                                       AEX (nested exception)
  |        |  RUNNING -------> FIRST_LEVEL_EXCEPTION_HANDLING <----------------------------
  |        |   |  ^ ^             |                       |                                |
  |        |   |  | |             |                       v                                |
  |        |   |  |  -------------                       SECOND_LEVEL_EXCEPTION_HANDLING --
  |        |   |  |   illegal instruction emulation              |       |          ^
  |        v   v  |                                              |       |          |
  |       EXITED   ----------------------------------------------         ----------
  |        |          (non-nested) exception handling is done              OCALL during
   --------                                                                exception
```

Details for each state are as follows.

- `NULL`

   The initial state of a thread, which can only transit to the `ENTERED` state.

- `ENTERED`

  The state indicates that the thread has entered the enclave via a non-exception handling
  path. When entering the state, the OE runtime also clears the previous state saved
  in thread data (`td`), which ensures the future exiting flow updates the state correctly
  (see `EXITED` for more detail). Note that a special case that the non-exception handling
  path does not update the state is when the thread is in
  `SECOND_LEVEL_EXCEPTION_HANDLING`. This case indicates that the entering flow is
  triggered by an OCALL made by the exception handling code. Such logic is represented as
  follows.

  ```c
  if (td->state != SECOND_LEVEL_EXCEPTION_HANDLING)
  {
      td->previous_state = NULL;
      td->state = ENTERED;
  }
  ```

- `RUNNING`

  The state indicates the enclave is executing an ECALL. Two state transition paths
  include:

  - a. The host makes an ECALL that enters the enclave, and the enclave finishes the necessary
       initialization for executing the ECALL.

  - b. The enclave makes an OCALL during an ECALL. and the host returns after executing the
       OCALL.

  In both paths, the state is transitioned from `ENTERED` to `RUNNING`. The OE runtime
  explicitly blocks the state transition from states other than `ENTERED` to `RUNNING`.

  The enclave in the `RUNNING` state allows the host to request in-enclave exception handling when an AEX occurs. The types of requests include:

  - a. Non-nested exception handling on hard failures (recognized by SGX hardware)

  - b. An interrupt handling

  After the enclave accepts the request, the state turns into
  `FIRST_LEVEL_EXCEPTION_HANDLING`, which reflects the stage of internal two-stage
  exception handling logic. Note that, this is the only state that allows an
  interrupt request. However, accepting the request requires meeting several conditions
  (see [thread interrupt](#thread-interrupt-on-linux) for more detail).

- `FIRST_LEVEL_EXCEPTION_HANDLING`

  The state represents that the thread is executing the first-level exception handler.
  The state can be transitioned from `RUNNING` and `SECOND_LEVEL_EXCEPTION_HANDLING`,
  which indicates non-nested and nested exception handling. The OE runtime performs
  such state checks upon an exception entry based on the `exception_nesting_level`
  stored in `td`. The runtime increases the variable on each accepted exception handling
  request and decreases the variable before resuming the execution. The execution resuming
  paths include:

  - a. The emulation of default illegal instructions (e.g., cpuid)

  - b. Normal exception handling

  In the first path, the runtime will restore the state to the previous state saved in
  `td` on each successful exception entry and then resume execution. In addition, the
  runtime will update the previous state to `FIRST_LEVEL_EXCEPTION_HANDLING`.
  In the second path, the runtime will update the state to `SECOND_LEVEL_EXCEPTION_HANDLING`
  and continue the execution (i.e., executing the second stage of the exception handling).
  The above logic is captured as follows.

  ```c
  if (td->exception_nesting_level == 0)
      if (td->state != RUNNING)
          return;
  else
      if (td->state != SECOND_LEVEL_EXCEPTION_HANDLING)
          return;

  td->previous_state = td->state;
  td->state = FIRST_LEVEL_EXCEPTION_HANDLING;
  td->exception_nesting_level++;

  ...

  if (illegal_instruction_emulation)
  {
      td->exception_nesting_level--;

      td->state = td->previous_state;
      td->previous_state = FIRST_LEVEL_EXCEPTION_HANDLING;
  }
  else
      td->state = SECOND_LEVEL_EXCEPTION_HANDLING;
  ```

- `SECOND_LEVEL_EXCEPTION_HANDLING`

  The state represents that the thread is executing the second-level exception
  handler. The state can only be entered from `FIRST_LEVEL_EXCEPTION_HANDLING`.
  The state could return to `FIRST_LEVEL_EXCEPTION_HANDLING` if an AEX
  occurs (i.e., nested exceptions). After finishing the exception handling,
  the runtime will decrease the nesting level by one and then check against
  the level. If the nesting level is zero, the state will be restored to
  `RUNNING` before resuming the execution.
  Also, the runtime will always clear the `previous_state`
  which ensures the future exiting flow updates the state correctly
  (see `EXITED` state for more detail). The above logic is as follows.

  ```c
  // After exception handlers

  if (td->exception_nesting_level == 0)
      abort();

  td->exception_nesting_level--;
  if (td->exception_nesting_level == 0)
  {
      td->state = RUNNING;
  }
  td->previous_state = NULL;
  ```

- `EXITED`

  The state indicates that the thread is about to leave the enclave, which occurs when
  the thread performs the exiting flow. Examples include when the thread makes
  an OCALL or finishes an ECALL when running in the `RUNNING` state, and the thread directly
  returns to the host after entering the `ENTERED` state. The latter flow can be triggered
  if the validation check fails in the enclave entering logic. Note that the following
  special cases of existing flow do not cause the state transition.

  - a. The thread exits from an exception entry (if the `previous_state` equals
    `FIRST_LEVEL_EXCEPTION_HANDLING` or `state` equals `SECOND_LEVEL_EXCEPTION_HANDLING`).

  - b. The thread makes an OCALL while running in the`SECOND_LEVEL_EXCEPTION_HANDLING`.

  The logic is as follows.
  ```c
  if (td->state != SECOND_LEVEL_EXCEPTION_HANDLING &&
      td->previous != FIRST_LEVEL_EXCEPTION_HANDLING)
    td->state = EXITED;
  ```

- `ABORTED`

  The state (not shown in the diagram above) indicates that the thread
  has been aborted because of unexpected failures. Any state can be transitioned
  into this state.

# Thread Interrupt on Linux

Thread interrupt is a special case of the exception handling flow that the OE runtime
supports on Linux. The state transition flow during a thread interrupt is shown as follows.

```
Thread 1                                  Thread 2 (td2)
--------                                  ---------
[ENCLAVE]                                 [ENCLAVE]
oe_sgx_register_td_host_signal(           RUNNING
  td2, SIGUSR1);                           oe_sgx_td_unmask_host_signal();
  |                                         |
  v                                         |
OCALL with SIGUSR1                          |
  |                                         |
   --> [HOST]                               |
       syscall(                             |
         sys_tgkill, pid, tid, SIGUSR1);    |
          |           interrupt             |
           -------------------------------> |         AEX
                                             ---------------------> [HOST]
                                      EENTER (signal_number=SIGUSR1) |
                                          [ENCLAVE] <----------------
                                            | if signal_number == 0 || signal_number > 64
                                            |--------------------------------> FIRST_LEVEL_EXCEPTION_HANDLING
                                            | if !td->interrupt_unmasked
                                            |--------------------------------> EXITED
                                            | if !(td->host_signal_bitmask & (signal_number -1))
                                            |--------------------------------> EXITED
                                            | if td->state != RUNNING
                                            |--------------------------------> EXITED
                                            | if td->is_handling_host_signal == 1
                                            |--------------------------------> EXITED
                                            | if td->exception_nesting_level != 0
                                            |--------------------------------> EXITED
                                            |
                                            td->is_handling_host_signal = 1;
                                            td->exception_nesting_level++;
                                            td->previous_state = td->state;
                                            td->host_signal = signal_number;
                                            |
                                            v
                                           FIRST_LEVEL_EXCEPTION_HANDLING <--
                                            |                                |
                                            v                                | nested
                                       ---> SECOND_LEVEL_EXCEPTION_HANDLING  | exception
                                      |     | (interrupt handling...)        |
                                OCALL |     |                                |
                                      |      ---------------------------> [HOST]
                                      |                                     |
                                       -------------------------------------|
                                                             ERESUME        |
                                           [ENCLAVE] <----------------------
                                           (interrupt handling done)
                                            | if td->exception_nesting_level == 0
                                            |--------------------------------> ABORTED
                                            td->exception_nesting_level--;
                                            | if td->exception_nesting_level == 0
                                            |   if td->is_handling_host_signal == 1
                                            |
                                            td->is_handling_host_signal = 0;
                                            td->host_signal = 0;
                                            |
                                            v
                                          RUNNING
                                          (continue exection)
```

The following provides the detail of the thread interrupt flow.

- Interrupting a thread

  We assume the scenario of two enclave threads where `thread 1` initiates
  an interrupt signal via an OCALL that targets `thread 2`. To hint at `thread 2`,
  `thread 1` must register the signal, which will serve as the interrupt
  signal, for `thread 2` (via an internal API `oe_sgx_register_td_host_signal`).
  Optionally, the `thread 2` can register the signal for itself.
  When the signal arrives, `thread 2` will execute the AEX flow and exits the
  enclave. The host will then follow up with an exception handling request
  along with the signal number (sent by the Linux kernel) to the enclave.

- Checking the interrupt request

  To determine whether to accept the interrupt request, the OE performs several
  checks in the exception entry path.

  - Signal number

    The runtime firstly checks the signal number that the host passes in along
    with the interrupt request. The value the signal indicates the request is
    an interrupt request or normal exception handling request (i.e., on a hard
    failure); i.e., if the value falls in the range of `(0, 64]`, which is the
    valid range of the signal number on Linux, the runtime treats the request
    as an interrupt request. Otherwise, the runtime will proceed with the execution
    of a normal exception handling path. Note that the first-level exception
    handling logic will reject the request if the SGX hardware does not provide
    valid information about the exception, which prevents the untrusted host
    to make a fake exception handling request.

  - `host_signal_unmasked`

    After checking the signal number and determining the request is indeed an
    interrupt request, the runtime then checks if the thread has unmasked the
    interrupt already. This is generally done by the thread itself via the
    internal API `oe_sgx_td_unmask_host_signal`. If the check passes, the runtime
    proceeds with the next check. Otherwise, the runtime performs the direct return
    path (the state is transitioned to `EXITED`)

  - `host_signal_bitmask`

    The `td` maintains a 64-bit bitmask that indicates which host signal is
    registered (via `oe_sgx_register_td_host_signal`). The runtime checks the
    signal number against the bitmask and proceeds with the next check is the
    corresponding bit of the signal number is set in the bitmask.

  - `state`

  As mentioned earlier, the `RUNNING` state is the only state that allows an
  interrupt request. The runtime also validates the state as part of checks.

  - `is_handling_host_signal`

  The `td` also maintains a flag that indicates whether the thread is currently
  handling the interrupt request. If the flag is already set, then the runtime
  will block any upcoming interrupt request, which prevents the nested interrupts.

  - `exception_nesting_level`

  Finally, the runtime ensures that the interrupt request is made during an ECALL
  instead of the exception handling (i.e., the `exception_nesting_level` should be 0).

  After all the above checks pass, the runtime updates the necessary fields in
  `td`. The overall logic is shown as the `diff` against the state transition
  logic of the `FIRST_LEVEL_EXCEPTION_HANDLING`.

  ```diff
  if (td->exception_nesting_level == 0)
      if (td->state != RUNNING)
          return;
  else
      if (td->state != SECOND_LEVEL_EXCEPTION_HANDLING)
          return;

  +if (signal_number > 0 && signal_number <= 64)
  +{
  +   if (!td->host_signal_unmasked)
  +       return;
  +
  +   if (!(td->host_signal_bitmask & (signal_number - 1)))
  +       return;
  +
  +   if (td->state != RUNNING)
  +       return;
  +
  +   if (td->is_handling_host_signal == 1)
  +       return;
  +
  +   if (td->exception_nesting_level != 0)
  +       return;
  +
  +   td->is_handling_host_signal = 1;
  +   td->host_signal = signal_number;
  +}

  td->previous_state = td->state;
  td->state = FIRST_LEVEL_EXCEPTION_HANDLING;
  td->exception_nesting_level++;

  ```

- Checking after interrupt handling

  After serving the interrupt request, the runtime checks if the nesting level is zero.
  If the check passes, the runtime clears the `is_handling_host_signal` flag. Also, the runtime always
  clears the `host_signal` when a non-nested exception handler finishies.
  Next, the runtime restores the state to `RUNNING`, indicating the interrupt handling has
  finished. The above logic is shown as the `diff` to the state transition logic of
  `SECOND_LEVEL_EXCEPTION_HANDLING`.

  ```diff
  if (td->exception_nesting_level == 0)
      abort();

  td->exception_nesting_level--;
  if (td->exception_nesting_level == 0)
  {
  +   if (td->is_handling_host_signal == 1)
  +   {
  +       td->is_handling_host_signal = 0;
  +   }
  +   td->host_signal = 0;
      td->state = RUNNING;
  }
  td->previous_state = NULL;
  ```

Authors
-------

- Ming-Wei Shih <mishih@microsoft.com>
