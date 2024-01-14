#ifndef _MSC_VER
#include "../../includes/compiler.h"

void* get_address_after_call() { return __builtin_return_address(0); }
#endif