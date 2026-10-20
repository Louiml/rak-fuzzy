/*
 * rak-fuzzy - the exported C interface.
 *
 * Rules that hold for every function in this file:
 *
 *   * every pointer, length and capacity is validated before use;
 *   * nothing is ever written past `out_cap`;
 *   * results are written into caller supplied buffers only;
 *   * no C++ object, no exception and no STL type crosses the boundary;
 *   * the library keeps no mutable global state, so calls are thread safe.
 */

#include "../include/rak_fuzzy.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "cluster.hpp"
#include "ctph.hpp"
#include "tlsh_like.hpp"

namespace {

/* Copy `text` into `out`, respecting `out_cap`. */
int write_string(const std::string& text, char* out, std::uint64_t out_cap) {
  if (out == nullptr) {
    return RF_ERR_NULL;
  }
  const std::uint64_t needed = static_cast<std::uint64_t>(text.size()) + 1u;
  if (out_cap < needed) {
    /* Nothing is written when the buffer is too small, so the caller never
     * sees a half written hash. */
    if (out_cap >= 1u) {
      out[0] = '\0';
    }
    return RF_ERR_CAPACITY;
  }
  std::memcpy(out, text.c_str(), text.size());
  out[text.size()] = '\0';
  return RF_OK;
}

#if defined(RAK_FUZZY_ENABLE_TLSH)
constexpr bool kTlshAvailable = true;
#else
constexpr bool kTlshAvailable = false;
#endif

} /* namespace */

extern "C" {

RF_API int rf_hash_buffer(const std::uint8_t* data, std::uint64_t len,
                           char* out, std::uint64_t out_cap) {
  if (out == nullptr) {
    return RF_ERR_NULL;
  }
  if (data == nullptr && len != 0) {
    return RF_ERR_NULL;
  }
  if (out_cap == 0) {
    return RF_ERR_CAPACITY;
  }
  if (len > static_cast<std::uint64_t>(SIZE_MAX)) {
    return RF_ERR_RANGE;
  }
  const rkf::HashResult result =
      rkf::hash_buffer(data, static_cast<std::size_t>(len));
  return write_string(rkf::format_hash(result), out, out_cap);
}

RF_API int rf_hash_file(const char* path, char* out, std::uint64_t out_cap) {
  if (path == nullptr || out == nullptr) {
    return RF_ERR_NULL;
  }
  if (out_cap == 0) {
    return RF_ERR_CAPACITY;
  }
  rkf::HashResult result;
  if (!rkf::hash_file(path, result)) {
    if (out_cap >= 1u) {
      out[0] = '\0';
    }
    return RF_ERR_IO;
  }
  return write_string(rkf::format_hash(result), out, out_cap);
}

RF_API int rf_compare(const char* hash_a, const char* hash_b) {
  if (hash_a == nullptr || hash_b == nullptr) {
    return RF_ERR_NULL;
  }
  return rkf::compare_hash_text(hash_a, hash_b);
}

RF_API int rf_cluster(const char* hashes_joined, std::uint64_t n, int threshold,
                      std::int32_t* cluster_ids_out) {
  if (cluster_ids_out == nullptr) {
    return RF_ERR_NULL;
  }
  if (hashes_joined == nullptr && n != 0) {
    return RF_ERR_NULL;
  }
  if (threshold < 0 || threshold > 100) {
    return RF_ERR_RANGE;
  }
  if (n > static_cast<std::uint64_t>(SIZE_MAX)) {
    return RF_ERR_RANGE;
  }
  if (n == 0) {
    return RF_OK;
  }

  /* Split the joined string into exactly n lines. */
  const char* end = hashes_joined;
  std::vector<rkf::ParsedHash> parsed;
  parsed.reserve(static_cast<std::size_t>(n));
  for (std::uint64_t i = 0; i < n; ++i) {
    const char* newline = std::strchr(end, '\n');
    const char* stop = (newline != nullptr) ? newline : end + std::strlen(end);
    rkf::ParsedHash parsed_hash;
    if (!rkf::parse_hash(end, stop, parsed_hash)) {
      return RF_ERR_FORMAT;
    }
    parsed.push_back(parsed_hash);
    if (newline == nullptr) {
      if (i + 1u != n) {
        return RF_ERR_FORMAT; /* fewer lines than announced */
      }
      end = stop;
      break;
    }
    end = newline + 1;
  }
  /* There must not be any extra line behind the announced ones. */
  if (*end != '\0') {
    return RF_ERR_FORMAT;
  }

  return rkf::cluster_hashes(parsed.data(), parsed.size(), threshold,
                             cluster_ids_out);
}

RF_API int rf_tlsh_buffer(const std::uint8_t* data, std::uint64_t len,
                           char* out, std::uint64_t out_cap) {
  if (out == nullptr) {
    return RF_ERR_NULL;
  }
  if (data == nullptr && len != 0) {
    return RF_ERR_NULL;
  }
  if (out_cap == 0) {
    return RF_ERR_CAPACITY;
  }
  if (!kTlshAvailable) {
    if (out_cap >= 1u) {
      out[0] = '\0';
    }
    return RF_ERR_UNSUPPORTED;
  }
  if (len > static_cast<std::uint64_t>(SIZE_MAX)) {
    return RF_ERR_RANGE;
  }
#if defined(RAK_FUZZY_ENABLE_TLSH)
  const std::string digest =
      rkf::tlsh_buffer(data, static_cast<std::size_t>(len));
  return write_string(digest, out, out_cap);
#else
  (void)data;
  (void)len;
  return RF_ERR_UNSUPPORTED;
#endif
}

RF_API int rf_tlsh_distance(const char* digest_a, const char* digest_b) {
  if (digest_a == nullptr || digest_b == nullptr) {
    return RF_ERR_NULL;
  }
  if (!kTlshAvailable) {
    return RF_ERR_UNSUPPORTED;
  }
#if defined(RAK_FUZZY_ENABLE_TLSH)
  return rkf::tlsh_distance(std::string(digest_a), std::string(digest_b));
#else
  (void)digest_a;
  (void)digest_b;
  return RF_ERR_UNSUPPORTED;
#endif
}

RF_API const char* rf_version(void) {
  return "rak-fuzzy 1.0.0 (ctph + tlsh-like)";
}

} /* extern "C" */
