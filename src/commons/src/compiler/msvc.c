#ifdef _MSC_VER
#include <intrin.h>
#include "../../includes/compiler.h"

void* get_address_after_call() { return _ReturnAddress(); }
#endif