/*
 * rak-fuzzy - unit tests for clustering and for the robustness of the
 * exported entry points.
 *
 * No test framework: the file contains a tiny harness (CHECK / CHECK_EQ).
 */

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "../include/rak_fuzzy.h"

namespace {

int g_checks = 0;
int g_failures = 0;
const char* g_case = "";

#define CHECK(cond)                                                       \
  do {                                                                    \
    ++g_checks;                                                           \
    if (!(cond)) {                                                        \
      ++g_failures;                                                       \
      std::printf("FAIL [%s] %s:%d: %s\n", g_case, __FILE__, __LINE__,    \
                  #cond);                                                 \
    }                                                                     \
  } while (0)

#define CHECK_EQ_INT(a, b)                                                \
  do {                                                                    \
    ++g_checks;                                                           \
    const long long va = (long long)(a);                                  \
    const long long vb = (long long)(b);                                  \
    if (va != vb) {                                                       \
      ++g_failures;                                                       \
      std::printf("FAIL [%s] %s:%d: %s == %s (%lld vs %lld)\n", g_case,   \
                  __FILE__, __LINE__, #a, #b, va, vb);                     \
    }                                                                     \
  } while (0)

class Rng {
 public:
  explicit Rng(std::uint64_t seed)
      : state_(seed ? seed : 0x9E3779B97F4A7C15ull) {}
  std::uint32_t next() {
    state_ ^= state_ << 13;
    state_ ^= state_ >> 7;
    state_ ^= state_ << 17;
    return static_cast<std::uint32_t>(state_ >> 32);
  }
  void fill(std::uint8_t* data, std::size_t len) {
    for (std::size_t i = 0; i < len; ++i) {
      data[i] = static_cast<std::uint8_t>(next() & 0xFFu);
    }
  }

 private:
  std::uint64_t state_;
};

std::string hash_buffer(const std::vector<std::uint8_t>& data) {
  std::string out(RF_HASH_OUT_CAPACITY + 16, '\0');
  const int rc = rf_hash_buffer(data.data(), data.size(), &out[0], out.size());
  if (rc != RF_OK) {
    std::printf("FAIL: rf_hash_buffer returned %d\n", rc);
    ++g_failures;
    return std::string();
  }
  out.resize(std::strlen(out.c_str()));
  return out;
}

std::string join(const std::vector<std::string>& items) {
  std::string out;
  for (std::size_t i = 0; i < items.size(); ++i) {
    if (i != 0) {
      out.push_back('\n');
    }
    out.append(items[i]);
  }
  return out;
}

/* ------------------------------------------------------------------ */

void test_clustering_basics() {
  g_case = "cluster basics";
  Rng rng(11);
  std::vector<std::uint8_t> base(60000);
  rng.fill(base.data(), base.size());
  const std::string h_base = hash_buffer(base);

  /* A second, unrelated file. */
  std::vector<std::uint8_t> other(60000);
  rng.fill(other.data(), other.size());
  const std::string h_other = hash_buffer(other);

  /* A slightly modified copy of the base file. */
  std::vector<std::uint8_t> copy = base;
  copy[30000] ^= 0x5Au;
  const std::string h_copy = hash_buffer(copy);

  const std::vector<std::string> hashes = {h_base, h_other, h_copy};
  const std::string joined = join(hashes);
  std::vector<std::int32_t> ids(hashes.size(), -1);

  CHECK_EQ_INT(rf_cluster(joined.c_str(), hashes.size(), 60, ids.data()),
               RF_OK);
  /* The base file and its modified copy belong together, the unrelated file
   * does not. */
  CHECK_EQ_INT(ids[0] == ids[2], 1);
  CHECK_EQ_INT(ids[0] != ids[1], 1);
  /* Clusters are numbered by first appearance. */
  CHECK_EQ_INT(ids[0], 0);
}

void test_cluster_numbering() {
  g_case = "cluster numbering";
  /* Three completely different files. */
  Rng rng(22);
  std::vector<std::string> hashes;
  for (int i = 0; i < 3; ++i) {
    std::vector<std::uint8_t> data(20000);
    rng.fill(data.data(), data.size());
    hashes.push_back(hash_buffer(data));
  }
  const std::string joined = join(hashes);
  std::vector<std::int32_t> ids(3, -1);
  CHECK_EQ_INT(rf_cluster(joined.c_str(), 3, 60, ids.data()), RF_OK);
  CHECK_EQ_INT(ids[0], 0);
  CHECK_EQ_INT(ids[1], 1);
  CHECK_EQ_INT(ids[2], 2);
  CHECK_EQ_INT(ids[0] != ids[1] && ids[1] != ids[2] && ids[0] != ids[2], 1);
}

void test_cluster_threshold() {
  g_case = "cluster threshold";
  Rng rng(33);
  std::vector<std::uint8_t> base(60000);
  rng.fill(base.data(), base.size());
  std::vector<std::uint8_t> copy = base;
  copy[1000] ^= 0x01u;
  const std::string a = hash_buffer(base);
  const std::string b = hash_buffer(copy);

  const std::string joined = a + "\n" + b;
  std::vector<std::int32_t> ids(2, -1);
  /* With an impossible threshold nothing is joined. */
  CHECK_EQ_INT(rf_cluster(joined.c_str(), 2, 100, ids.data()), RF_OK);
  CHECK_EQ_INT(ids[0] != ids[1], 1);
  /* With a threshold of zero everything is joined. */
  CHECK_EQ_INT(rf_cluster(joined.c_str(), 2, 0, ids.data()), RF_OK);
  CHECK_EQ_INT(ids[0] == ids[1], 1);
  /* An out of range threshold is refused. */
  CHECK_EQ_INT(rf_cluster(joined.c_str(), 2, 101, ids.data()), RF_ERR_RANGE);
  CHECK_EQ_INT(rf_cluster(joined.c_str(), 2, -1, ids.data()), RF_ERR_RANGE);
}

void test_cluster_errors() {
  g_case = "cluster errors";
  std::vector<std::int32_t> ids(4, -1);
  CHECK_EQ_INT(rf_cluster(nullptr, 2, 50, ids.data()), RF_ERR_NULL);
  CHECK_EQ_INT(rf_cluster("3:AA:BB", 2, 50, ids.data()), RF_ERR_FORMAT);
  CHECK_EQ_INT(rf_cluster("3:AA:BB", 1, 50, nullptr), RF_ERR_NULL);
  CHECK_EQ_INT(rf_cluster("not a hash", 1, 50, ids.data()), RF_ERR_FORMAT);
}

/*
 * Fuzzing: random and malformed hash strings must never crash the compare
 * or the cluster entry point. The library is expected to return an error
 * code or a score, never to read out of bounds.
 */
void test_fuzz() {
  g_case = "fuzz";
  static const char* kGarbage[] = {
      "",
      ":",
      "::",
      "3:",
      "3::",
      "3",
      "3:",
      ":AA:BB",
      "abc:AA:BB",
      "3:AA:BB:CC",
      "3:AA!BB",
      "3:AA:BB!",
      "3:AA:BB ",
      " 3:AA:BB",
      "99999999999999999999:AA:BB",
      "4294967295:AA:BB",
      "0:AA:BB",
      "3:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:BB",
      "3:AA:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
      "\x01\x02\x03:AA:BB",
      "3:\xff\xfe:BB",
      "18446744073709551616:AA:BB",
  };
  const std::size_t count = sizeof(kGarbage) / sizeof(kGarbage[0]);

  for (std::size_t i = 0; i < count; ++i) {
    for (std::size_t j = 0; j < count; ++j) {
      const int score = rf_compare(kGarbage[i], kGarbage[j]);
      /* Only a score in 0..100 or a negative error code is allowed. */
      CHECK((score >= 0 && score <= 100) || score < 0);
    }
    std::vector<std::int32_t> ids(1, -1);
    const int rc = rf_cluster(kGarbage[i], 1, 50, ids.data());
    CHECK(rc == RF_OK || rc < 0);
  }

  /* Random bytes as hash strings. */
  Rng rng(4711);
  for (int round = 0; round < 4000; ++round) {
    char buffer[128];
    const std::size_t len = 1 + (rng.next() % 100u);
    for (std::size_t i = 0; i < len; ++i) {
      buffer[i] = static_cast<char>(rng.next() & 0xFFu);
    }
    buffer[len] = '\0';
    const int score = rf_compare(buffer, buffer);
    CHECK((score >= 0 && score <= 100) || score < 0);

    std::vector<std::int32_t> ids(3, -1);
    const int rc = rf_cluster(buffer, 1, 50, ids.data());
    CHECK(rc == RF_OK || rc < 0);
  }

  /* Random strings that look almost like hashes. */
  static const char kAlphabet[] =
      "0123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";
  for (int round = 0; round < 4000; ++round) {
    char buffer[160];
    const std::size_t len = 1 + (rng.next() % 120u);
    for (std::size_t i = 0; i < len; ++i) {
      buffer[i] = kAlphabet[rng.next() % (sizeof(kAlphabet) - 1)];
    }
    buffer[len] = '\0';
    const int score = rf_compare(buffer, buffer);
    CHECK((score >= 0 && score <= 100) || score < 0);

    std::vector<std::int32_t> ids(3, -1);
    const int rc = rf_cluster(buffer, 1, 50, ids.data());
    CHECK(rc == RF_OK || rc < 0);
  }
}

/* Many hashes at once: the clustering path must stay stable. */
void test_cluster_scale() {
  g_case = "cluster scale";
  Rng rng(555);
  std::vector<std::string> hashes;
  std::vector<std::uint8_t> base(200000);
  rng.fill(base.data(), base.size());
  for (int i = 0; i < 40; ++i) {
    std::vector<std::uint8_t> data = base;
    /* Up to three modified bytes: the copies must still be recognised as
     * variants of the same file. */
    for (int k = 0; k < (i % 4); ++k) {
      data[static_cast<std::size_t>(rng.next() % data.size())] ^= 0x11u;
    }
    hashes.push_back(hash_buffer(data));
  }
  const std::string joined = join(hashes);
  std::vector<std::int32_t> ids(hashes.size(), -1);
  CHECK_EQ_INT(rf_cluster(joined.c_str(), hashes.size(), 50, ids.data()),
               RF_OK);
  /* All of them are variants of the same file, so they must end up in one
   * cluster. */
  for (std::size_t i = 1; i < ids.size(); ++i) {
    CHECK_EQ_INT(ids[i] == ids[0], 1);
  }
}

void test_tlsh() {
  g_case = "tlsh";
  Rng rng(9090);
  std::vector<std::uint8_t> data(200000);
  rng.fill(data.data(), data.size());
  std::string digest(RF_TLSH_OUT_CAPACITY + 8, '\0');
  const int rc = rf_tlsh_buffer(data.data(), data.size(), &digest[0],
                                digest.size());
  if (rc == RF_ERR_UNSUPPORTED) {
    std::printf("  TLSH not built in, skipping\n");
    return;
  }
  CHECK_EQ_INT(rc, RF_OK);
  digest.resize(std::strlen(digest.c_str()));
  CHECK_EQ_INT(digest.size(), 26);
  CHECK_EQ_INT(digest.compare(0, 2, "T1"), 0);

  /* The same data gives the same digest, and a distance of zero. */
  std::string digest2(RF_TLSH_OUT_CAPACITY + 8, '\0');
  CHECK_EQ_INT(rf_tlsh_buffer(data.data(), data.size(), &digest2[0],
                               digest2.size()),
               RF_OK);
  digest2.resize(std::strlen(digest2.c_str()));
  CHECK_EQ_INT(digest == digest2, 1);
  CHECK_EQ_INT(rf_tlsh_distance(digest.c_str(), digest2.c_str()), 0);

  /* A different file has a positive distance. */
  std::vector<std::uint8_t> other(200000);
  rng.fill(other.data(), other.size());
  std::string digest3(RF_TLSH_OUT_CAPACITY + 8, '\0');
  CHECK_EQ_INT(rf_tlsh_buffer(other.data(), other.size(), &digest3[0],
                              digest3.size()),
               RF_OK);
  digest3.resize(std::strlen(digest3.c_str()));
  const int distance = rf_tlsh_distance(digest.c_str(), digest3.c_str());
  std::printf("  tlsh distance (different)  -> %d\n", distance);
  CHECK(distance > 0);

  /* Malformed digests are refused, not crashed on. */
  CHECK(rf_tlsh_distance("nonsense", digest.c_str()) < 0);
  CHECK(rf_tlsh_distance(digest.c_str(), "nonsense") < 0);
  CHECK_EQ_INT(rf_tlsh_distance(nullptr, digest.c_str()), RF_ERR_NULL);
}

} /* namespace */

int main() {
  std::printf("rak-fuzzy cluster tests\n");
  test_clustering_basics();
  test_cluster_numbering();
  test_cluster_threshold();
  test_cluster_errors();
  test_cluster_scale();
  test_tlsh();
  test_fuzz();

  std::printf("%d checks, %d failures\n", g_checks, g_failures);
  return g_failures == 0 ? 0 : 1;
}
