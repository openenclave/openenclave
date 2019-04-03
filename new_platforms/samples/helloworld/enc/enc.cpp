// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <stdio.h>
extern "C"{
  #include <user_ta_header.h>

  void* __gcc_personality_v0;
}

#include "helloworld_t.h"

void ecall_InitializeStdio(void)
{

}

static void deal_with_result(oe_result_t result)
{
  if (result != OE_OK)
  {
    fprintf(
      stderr,
      "Call to host_print failed: result=%u (%s)\n",
      result,
      oe_result_str(result));
  }
}

class TestClass {
  int i;
  
  public:
    TestClass()
    {
      int retval;
      host_print(&retval, "Hello from constructor!");
    }

    ~TestClass()
    {
      int retval;
      host_print(&retval, "Hello from destructor!");
    }

    int get_i();
    void put_i(int j);
    void thrw();
};

int TestClass::get_i()
{
  return i;
}

void TestClass::put_i(int j)
{
  i = j;
}

void TestClass::thrw()
{
  int retval;
  oe_result_t result;

  try {
    result = host_print(&retval, "Throwing 11.");
    deal_with_result(result);
    throw 11;
  } catch(...) {
    result = host_print(&retval, "Caught 11, throwing 42.");
    deal_with_result(result);
    throw 42;
  }
}

static TestClass *c = new TestClass();

int enclave_entry(void)
{
  int retval;
  oe_result_t result;

  char buf[128];

  void (**fn)(void);
  extern void (*__init_array_start)(void);
  extern void (*__init_array_end)(void);

  result = host_print(&retval, "Processing init array.");
  deal_with_result(result);
  for (fn = &__init_array_start; fn < &__init_array_end; fn++)
  {
      (*fn)();
  }

  result = host_print(&retval, "Reading some linker variables.");
  deal_with_result(result);
  extern volatile void (*__text_start)(void);
  sprintf(buf, "\t__text_start = %p.", &__text_start);
  result = host_print(&retval, buf);
  deal_with_result(result);
  
  extern volatile void (*__text_end)(void);
  sprintf(buf, "\t__text_end = %p.", &__text_end);
  result = host_print(&retval, buf);
  deal_with_result(result);

  //
  // Arrays
  //

  result = host_print(&retval, "Playing with an array.");
  deal_with_result(result);

  auto anArray = new int[10];
  delete[] anArray;

  //
  // Classes
  //

  result = host_print(&retval, "Creating a class instance.");
  deal_with_result(result);

  TestClass testInstance;

  result = host_print(&retval, "Playing with the instance.");
  deal_with_result(result);

  testInstance.put_i(10);
  auto value = testInstance.get_i();

  sprintf(buf, "The value is = %i.", value);
  result = host_print(&retval, buf);
  deal_with_result(result);

  //
  // Loader Data
  //

  result = host_print(&retval, "Finding out my RVA.");
  deal_with_result(result);

  uintptr_t rva = tahead_get_rva();
  sprintf(buf, "The RVA is %p", rva);

  result = host_print(&retval, buf);
  deal_with_result(result);

  //
  // Exceptions
  //
  sprintf(buf, "");
  try 
  {
    testInstance.thrw();
  }
  catch(...)
  {
    result = host_print(&retval, "Exception handler!");
    deal_with_result(result);
  }

  delete c;

  //
  // Done!
  //

  result = host_print(&retval, "Bye bye!");
  deal_with_result(result);

  extern void (*__fini_array_start)(void);
  extern void (*__fini_array_end)(void);

  result = host_print(&retval, "Processing fini array."); 
  deal_with_result(result);
  for (fn = &__fini_array_start; fn < &__fini_array_end; fn++)
  {
      (*fn)();
  }

  return result;
}
