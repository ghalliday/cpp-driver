/*
  Copyright 2014 DataStax

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#ifndef __CASS_COMMON_HPP_INCLUDED__
#define __CASS_COMMON_HPP_INCLUDED__

#include "cassandra.h"

#include "third_party/boost/boost/static_assert.hpp"

#include <uv.h>
#include <string.h>
#include <string>

namespace cass {

// copy_cast<> prevents incorrect code from being generated when two unrelated 
// types reference the same memory location and strict aliasing is enabled.
// The type "char*" is an exception and is allowed to alias any other 
// pointer type. This allows memcpy() to copy bytes from one type to the other
// without violating strict aliasing and usually optimizes away on a modern
// compiler (GCC, Clang, and MSVC).

template<typename From, typename To>
inline To copy_cast(const From& from)
{
  BOOST_STATIC_ASSERT(sizeof(From) == sizeof(To));

  To to;
  memcpy(&to, &from, sizeof(from));
  return to;
}

inline size_t next_pow_2(size_t num) {
  size_t next = 2;
  size_t i = 0;
  while (next < num) {
    next = static_cast<size_t>(1) << i++;
  }
  return next;
}
 
uv_buf_t alloc_buffer(size_t suggested_size);
uv_buf_t alloc_buffer(uv_handle_t* handle, size_t suggested_size);
void free_buffer(uv_buf_t buf);

std::string opcode_to_string(int opcode);

std::string& trim(std::string& str);

} // namespace cass

#endif
