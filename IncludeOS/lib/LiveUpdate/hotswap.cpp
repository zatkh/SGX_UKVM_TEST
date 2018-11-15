// This file is a part of the IncludeOS unikernel - www.includeos.org
//
// Copyright 2017 IncludeOS AS, Oslo, Norway
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
/**
 * Master thesis
 * by Alf-Andre Walla 2016-2017
 *
**/
asm(".org 0x8000");
#define SOFT_RESET_MAGIC   0xFEE1DEAD

extern "C" __attribute__((noreturn))
void hotswap(const char* base, int len, char* dest, void* start, void* reset_data)
{
  // replace old kernel with new
  for (int i = 0; i < len; i++)
    dest[i] = base[i];
  // jump to _start
  asm volatile("jmp *%2" : : "a" (SOFT_RESET_MAGIC), "b" (reset_data), "c" (start));
  asm volatile(
  ".global __hotswap_length;\n"
  "__hotswap_length:" );
  // we can never get here!
  __builtin_unreachable();
}
