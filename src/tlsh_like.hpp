/*
 * rak-fuzzy - internal interface of the TLSH-like digest.
 */

#ifndef RKF_TLSH_LIKE_HPP
#define RKF_TLSH_LIKE_HPP

#include <cstddef>
#include <cstdint>
#include <string>

namespace rkf {

/* Length of the rendered digest, excluding the NUL terminator. */
constexpr std::size_t kTlshDigestLen = 26;

/* Number of buckets the trigram counts are folded into. */
constexpr std::size_t kTlshBuckets = 128;

/* Compute the digest of a buffer. */
std::string tlsh_buffer(const std::uint8_t* data, std::size_t len);

/* Distance between two digests: 0 means identical, larger means different. */
int tlsh_distance(const std::string& a, const std::string& b);

} /* namespace rkf */

#endif /* RKF_TLSH_LIKE_HPP */
