#pragma once
#include "Runtime.hpp"
#include <string>
namespace hajimi::crypto {
// Portable BLAKE3 reference construction; O(log(input length)) chaining stack.
Buffer blake3(const Buffer &input, size_t count);
Buffer blake3Keyed(const Buffer &key, const Buffer &input, size_t count);
Buffer blake3DeriveKey(const std::string &context, const Buffer &material, size_t count);
}
