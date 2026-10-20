/*
 * rak-fuzzy - a simplified TLSH-style locality sensitive digest.
 *
 * This is *not* TLSH and it does not produce TLSH compatible digests. It
 * follows the same idea so that the two algorithms can be compared
 * conceptually, but every constant is documented here and the output format
 * is our own:
 *
 *   "T1" + checksum(4 hex) + length(8 hex) + q1(4) + q2(4) + q3(4)
 *
 * The algorithm:
 *
 *   1. Slide a 5 byte window over the input. The difference between the
 *      last and the first byte of the window ("diff") decides whether the
 *      window carries enough entropy to be counted; windows with a diff
 *      below 4 are skipped.
 *   2. Depending on the parity of the diff, either the first or the last
 *      trigram of the window is hashed into one of 128 buckets, whose
 *      counter is incremented.
 *   3. The 25th, 50th and 75th percentile of the non empty bucket counters
 *      form the quartiles q1 <= q2 <= q3. The digest stores the deltas
 *      q1, q2 - q1 and q3 - q2.
 *   4. The header carries a 16 bit checksum of the content and the length
 *      of the input modulo 2^32.
 *
 * The distance function compares the quartile deltas, weights the higher
 * quartiles more, and normalises the result by the largest quartile so
 * that digests of files of very different sizes stay comparable. Lower is
 * more similar; 0 means the digests are identical.
 */

#include "tlsh_like.hpp"

#include <algorithm>
#include <cstring>
#include <vector>

namespace rkf {
namespace {

/* Fixed point scale used to compare the quartiles as ratios. */
constexpr std::uint64_t kRatioScale = 65536u;

/* Avalanche mix, used to spread a 24 bit trigram over the buckets. */
inline std::uint32_t mix32(std::uint32_t x) {
  x ^= x >> 16;
  x *= 0x7feb352du;
  x ^= x >> 15;
  x *= 0x846ca68bu;
  x ^= x >> 16;
  return x;
}

/* 16 bit fold of a 32 bit FNV-1a hash of the content. */
std::uint16_t content_checksum(const std::uint8_t* data, std::size_t len) {
  std::uint32_t h = 2166136261u;
  for (std::size_t i = 0; i < len; ++i) {
    h = (h ^ data[i]) * 16777619u;
  }
  return static_cast<std::uint16_t>((h >> 16) ^ (h & 0xFFFFu));
}

/* Write `value` as `digits` lower case hex digits. */
void write_hex(std::string& out, std::uint64_t value, int digits) {
  static const char kHex[] = "0123456789abcdef";
  for (int i = digits - 1; i >= 0; --i) {
    out.push_back(kHex[(value >> (4 * i)) & 0xFull]);
  }
}

/* Read `digits` hex digits. Returns false on any invalid character. */
bool read_hex(const std::string& s, std::size_t offset, int digits,
              std::uint64_t& out) {
  std::uint64_t value = 0;
  for (int i = 0; i < digits; ++i) {
    const char c = s[offset + static_cast<std::size_t>(i)];
    std::uint64_t nibble;
    if (c >= '0' && c <= '9') {
      nibble = static_cast<std::uint64_t>(c - '0');
    } else if (c >= 'a' && c <= 'f') {
      nibble = static_cast<std::uint64_t>(c - 'a' + 10);
    } else if (c >= 'A' && c <= 'F') {
      nibble = static_cast<std::uint64_t>(c - 'A' + 10);
    } else {
      return false;
    }
    value = (value << 4) | nibble;
  }
  out = value;
  return true;
}

struct Digest {
  std::uint16_t checksum = 0;
  std::uint32_t length = 0;
  std::uint64_t q[3] = {0, 0, 0}; /* the three deltas */
};

/* Parse a digest string. Returns false when malformed. */
bool parse_digest(const std::string& text, Digest& out) {
  if (text.size() != kTlshDigestLen) {
    return false;
  }
  if (text.compare(0, 2, "T1") != 0) {
    return false;
  }
  std::uint64_t value = 0;
  if (!read_hex(text, 2, 4, value)) {
    return false;
  }
  out.checksum = static_cast<std::uint16_t>(value);
  if (!read_hex(text, 6, 8, value)) {
    return false;
  }
  out.length = static_cast<std::uint32_t>(value);
  for (int i = 0; i < 3; ++i) {
    if (!read_hex(text, 14 + i * 4, 4, value)) {
      return false;
    }
    out.q[i] = value;
  }
  return true;
}

} /* namespace */

std::string tlsh_buffer(const std::uint8_t* data, std::size_t len) {
  std::vector<std::uint32_t> buckets(kTlshBuckets, 0);

  if (data != nullptr && len >= 5) {
    for (std::size_t i = 0; i + 5 <= len; ++i) {
      const unsigned int diff =
          (static_cast<unsigned int>(data[i + 4]) + 256u -
           static_cast<unsigned int>(data[i])) &
          0xFFu;
      if (diff < 4u) {
        continue; /* not enough entropy in this window */
      }
      std::uint32_t trigram;
      if ((diff & 1u) == 0u) {
        trigram = (static_cast<std::uint32_t>(data[i]) << 16) |
                  (static_cast<std::uint32_t>(data[i + 1]) << 8) |
                  static_cast<std::uint32_t>(data[i + 2]);
      } else {
        trigram = (static_cast<std::uint32_t>(data[i + 2]) << 16) |
                  (static_cast<std::uint32_t>(data[i + 3]) << 8) |
                  static_cast<std::uint32_t>(data[i + 4]);
      }
      ++buckets[mix32(trigram) & (kTlshBuckets - 1)];
    }
  }

  /* Quartiles of the non empty bucket counters. */
  std::vector<std::uint32_t> counts;
  counts.reserve(kTlshBuckets);
  for (std::size_t i = 0; i < kTlshBuckets; ++i) {
    if (buckets[i] != 0) {
      counts.push_back(buckets[i]);
    }
  }
  std::sort(counts.begin(), counts.end());
  std::uint32_t q1 = 0;
  std::uint32_t q2 = 0;
  std::uint32_t q3 = 0;
  if (!counts.empty()) {
    const std::size_t n = counts.size();
    q1 = counts[n / 4];
    q2 = counts[n / 2];
    q3 = counts[(3 * n) / 4];
    if (3 * n / 4 >= n) {
      q3 = counts[n - 1];
    }
  }

  std::string out;
  out.reserve(kTlshDigestLen + 1);
  out.append("T1");
  write_hex(out, content_checksum(data, len), 4);
  write_hex(out, static_cast<std::uint64_t>(len) & 0xFFFFFFFFull, 8);
  write_hex(out, q1, 4);
  write_hex(out, q2 - q1, 4);
  write_hex(out, q3 - q2, 4);
  return out;
}

int tlsh_distance(const std::string& a, const std::string& b) {
  Digest da;
  Digest db;
  if (!parse_digest(a, da) || !parse_digest(b, db)) {
    return -4; /* RF_ERR_FORMAT */
  }

  /*
   * The quartiles grow with the size of the input, so they are compared as
   * ratios relative to the largest quartile. That keeps the distance
   * meaningful for inputs of very different sizes.
   */
  const std::uint64_t q3a = da.q[0] + da.q[1] + da.q[2];
  const std::uint64_t q3b = db.q[0] + db.q[1] + db.q[2];

  const std::uint64_t scale_a = (q3a == 0) ? 1 : q3a;
  const std::uint64_t scale_b = (q3b == 0) ? 1 : q3b;

  const std::uint64_t norm_a[3] = {
      (da.q[0] * kRatioScale) / scale_a, (da.q[1] * kRatioScale) / scale_a,
      (da.q[2] * kRatioScale) / scale_a};
  const std::uint64_t norm_b[3] = {
      (db.q[0] * kRatioScale) / scale_b, (db.q[1] * kRatioScale) / scale_b,
      (db.q[2] * kRatioScale) / scale_b};

  const std::uint64_t e1 = (norm_a[0] > norm_b[0]) ? norm_a[0] - norm_b[0]
                                                    : norm_b[0] - norm_a[0];
  const std::uint64_t e2 = (norm_a[1] > norm_b[1]) ? norm_a[1] - norm_b[1]
                                                    : norm_b[1] - norm_a[1];
  const std::uint64_t e3 = (norm_a[2] > norm_b[2]) ? norm_a[2] - norm_b[2]
                                                    : norm_b[2] - norm_a[2];

  /* Higher quartiles carry more information, so they weigh more. */
  const std::uint64_t raw = e1 + 2u * e2 + 3u * e3;

  std::uint64_t distance = (100ull * raw) / (3ull * kRatioScale);
  if (distance > 100) {
    distance = 100;
  }

  /* Different lengths are a hint that the content differs. */
  const std::uint64_t la = da.length;
  const std::uint64_t lb = db.length;
  const std::uint64_t biggest = la > lb ? la : lb;
  if (biggest > 0) {
    const std::uint64_t difference = la > lb ? la - lb : lb - la;
    std::uint64_t penalty = (100ull * difference) / biggest;
    if (penalty > 50) {
      penalty = 50;
    }
    distance += penalty;
  }

  /*
   * Quartiles are a very coarse summary, so two completely different files
   * of the same size can have identical quartiles. The content checksum is
   * the tie breaker: if it differs, the inputs are provably not the same,
   * and the distance is raised to at least one.
   */
  if (distance == 0 && da.checksum != db.checksum) {
    distance = 1;
  }

  if (distance > 100) {
    distance = 100;
  }
  return static_cast<int>(distance);
}

} /* namespace rkf */
