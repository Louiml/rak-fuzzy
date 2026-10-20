/*
 * rak-fuzzy - unit tests for the CTPH hashing and comparison.
 *
 * No test framework: the file contains a tiny harness (CHECK / CHECK_EQ) and
 * a set of self contained test cases.
 *
 *   test_ctph            run the test suite
 *   test_ctph --bench    additionally run the throughput benchmark
 */

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#include "../include/rak_fuzzy.h"

#if defined(_WIN32)
#  include <windows.h>
#  include <psapi.h>
#else
#  include <unistd.h>
#endif

/* ------------------------------------------------------------------ */
/* Tiny harness                                                         */
/* ------------------------------------------------------------------ */

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

/* Deterministic PRNG so the tests behave the same everywhere. */
class Rng {
 public:
  explicit Rng(std::uint64_t seed) : state_(seed ? seed : 0x9E3779B97F4A7C15ull) {}
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

/* Split "bs:sig1:sig2" into three parts. */
void split_hash(const std::string& hash, std::string& bs, std::string& s1,
                std::string& s2) {
  const std::size_t p1 = hash.find(':');
  bs = hash.substr(0, p1);
  const std::size_t p2 = hash.find(':', p1 + 1);
  s1 = hash.substr(p1 + 1, p2 - p1 - 1);
  s2 = hash.substr(p2 + 1);
}

/* Monotonic clock in microseconds. */
std::uint64_t now_micros() {
#if defined(_WIN32)
  LARGE_INTEGER frequency;
  LARGE_INTEGER counter;
  QueryPerformanceFrequency(&frequency);
  QueryPerformanceCounter(&counter);
  return static_cast<std::uint64_t>((counter.QuadPart * 1000000LL) /
                                    frequency.QuadPart);
#else
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return static_cast<std::uint64_t>(ts.tv_sec) * 1000000ull +
         static_cast<std::uint64_t>(ts.tv_nsec) / 1000ull;
#endif
}

std::size_t peak_memory_bytes() {
#if defined(_WIN32)
  PROCESS_MEMORY_COUNTERS pmc;
  if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
    return static_cast<std::size_t>(pmc.PeakWorkingSetSize);
  }
  return 0;
#else
  FILE* f = std::fopen("/proc/self/status", "r");
  if (f == nullptr) {
    return 0;
  }
  char line[256];
  std::size_t peak = 0;
  while (std::fgets(line, sizeof(line), f) != nullptr) {
    if (std::strncmp(line, "VmHWM:", 6) == 0) {
      unsigned long long kb = 0;
      if (std::sscanf(line + 6, "%llu", &kb) == 1) {
        peak = static_cast<std::size_t>(kb) * 1024u;
      }
      break;
    }
  }
  std::fclose(f);
  return peak;
#endif
}

/* ------------------------------------------------------------------ */
/* Test cases                                                           */
/* ------------------------------------------------------------------ */

void test_format_and_determinism() {
  g_case = "format";
  Rng rng(1234);
  std::vector<std::uint8_t> data(100000);
  rng.fill(data.data(), data.size());

  const std::string h1 = hash_buffer(data);
  const std::string h2 = hash_buffer(data);
  CHECK(!h1.empty());
  CHECK_EQ_INT(h1 == h2, 1);

  std::string bs;
  std::string s1;
  std::string s2;
  split_hash(h1, bs, s1, s2);
  CHECK(!bs.empty());
  CHECK(bs.find_first_not_of("0123456789") == std::string::npos);
  CHECK(s1.size() <= RF_MAX_SIG_CHARS);
  CHECK(s2.size() <= RF_MAX_SIG_CHARS);
  CHECK(!s1.empty());
  CHECK(!s2.empty());

  /* The same data must hash the same way through the file interface. */
  const char* path = "rak_fuzzy_test_tmp.bin";
  {
    FILE* f = std::fopen(path, "wb");
    CHECK(f != nullptr);
    if (f != nullptr) {
      std::fwrite(data.data(), 1, data.size(), f);
      std::fclose(f);
    }
    std::string out(RF_HASH_OUT_CAPACITY + 16, '\0');
    const int rc = rf_hash_file(path, &out[0], out.size());
    CHECK_EQ_INT(rc, RF_OK);
    out.resize(std::strlen(out.c_str()));
    CHECK_EQ_INT(out == h1, 1);
    std::remove(path);
  }
}

void test_identical_and_unrelated() {
  g_case = "identical/unrelated";
  Rng rng(99);
  std::vector<std::uint8_t> a(50000);
  std::vector<std::uint8_t> b(50000);
  rng.fill(a.data(), a.size());
  rng.fill(b.data(), b.size());

  const std::string ha = hash_buffer(a);
  const std::string hb = hash_buffer(b);

  CHECK_EQ_INT(rf_compare(ha.c_str(), ha.c_str()), 100);
  CHECK_EQ_INT(rf_compare(ha.c_str(), hb.c_str()), 0);
  CHECK_EQ_INT(rf_compare(hb.c_str(), ha.c_str()), 0);
}

void test_mutation_scores() {
  g_case = "mutation";
  const std::size_t kSize = 1024u * 1024u;
  Rng rng(4242);
  std::vector<std::uint8_t> original(kSize);
  rng.fill(original.data(), original.size());
  const std::string h0 = hash_buffer(original);

  /* A single flipped byte must change the score, but not destroy it. */
  {
    std::vector<std::uint8_t> mutated = original;
    mutated[kSize / 2] ^= 0xFFu;
    const std::string hm = hash_buffer(mutated);
    const int score = rf_compare(h0.c_str(), hm.c_str());
    std::printf("  flip one byte            -> %d\n", score);
    CHECK(score > 0);
    CHECK(score < 100);
    CHECK(score >= 50);
  }

  /* Appending a few bytes changes the trailing chunk. */
  {
    std::vector<std::uint8_t> mutated = original;
    mutated.push_back(0x41);
    mutated.push_back(0x42);
    const std::string hm = hash_buffer(mutated);
    const int score = rf_compare(h0.c_str(), hm.c_str());
    std::printf("  append two bytes          -> %d\n", score);
    CHECK(score > 0);
    CHECK(score < 100);
  }

  /* Deleting a few bytes does the same. */
  {
    std::vector<std::uint8_t> mutated = original;
    mutated.erase(mutated.begin() + 1000, mutated.begin() + 1004);
    const std::string hm = hash_buffer(mutated);
    const int score = rf_compare(h0.c_str(), hm.c_str());
    std::printf("  delete four bytes         -> %d\n", score);
    CHECK(score > 0);
    CHECK(score < 100);
  }

  /*
   * The bigger the damage, the smaller the score. The exact values depend
   * on where the chunk boundaries happen to fall, so the trend is checked
   * with a small tolerance instead of demanding strict monotonicity.
   */
  int previous = 100;
  const std::size_t sizes[] = {4096, 65536, 262144, 786432};
  int first = 100;
  int last = 0;
  for (std::size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i) {
    std::vector<std::uint8_t> mutated = original;
    Rng sub(static_cast<std::uint64_t>(sizes[i]));
    sub.fill(mutated.data(), sizes[i]);
    const std::string hm = hash_buffer(mutated);
    const int score = rf_compare(h0.c_str(), hm.c_str());
    std::printf("  replace %7zu bytes       -> %d\n", sizes[i], score);
    CHECK(score <= previous + 3);
    if (i == 0) {
      first = score;
    }
    last = score;
    previous = score;
  }
  CHECK(last < first);
  CHECK(last < 50);
}

void test_inserted_block() {
  g_case = "inserted block";
  const std::size_t kSize = 1024u * 1024u;
  Rng rng(777);
  std::vector<std::uint8_t> original(kSize);
  rng.fill(original.data(), original.size());
  const std::string h0 = hash_buffer(original);

  std::vector<std::uint8_t> modified = original;
  std::vector<std::uint8_t> block(4096);
  rng.fill(block.data(), block.size());
  modified.insert(modified.begin() + static_cast<long>(kSize / 2),
                  block.begin(), block.end());
  const std::string hm = hash_buffer(modified);
  const int score = rf_compare(h0.c_str(), hm.c_str());
  std::printf("  insert 4 KiB in the middle-> %d\n", score);
  CHECK(score > 50);
  CHECK(score < 100);
}

void test_block_size_neighbours() {
  g_case = "2x block size";
  Rng rng(31337);
  std::vector<std::uint8_t> data(200000);
  rng.fill(data.data(), data.size());
  const std::string h = hash_buffer(data);

  std::string bs;
  std::string s1;
  std::string s2;
  split_hash(h, bs, s1, s2);
  const unsigned long block = std::strtoul(bs.c_str(), nullptr, 10);

  /* A neighbour hash: twice the block size, carrying the coarse signature. */
  char neighbour[RF_HASH_OUT_CAPACITY + 16];
  std::snprintf(neighbour, sizeof(neighbour), "%lu:%s:%s",
                block * 2u, s2.c_str(), s1.c_str());
  const int score = rf_compare(h.c_str(), neighbour);
  std::printf("  1x vs 2x neighbour        -> %d\n", score);
  CHECK(score > 0);
  CHECK(score <= 100);

  /* Same block size, identical signature: a perfect match. */
  char same[RF_HASH_OUT_CAPACITY + 16];
  std::snprintf(same, sizeof(same), "%lu:%s:%s", block, s1.c_str(), s2.c_str());
  CHECK_EQ_INT(rf_compare(h.c_str(), same), 100);

  /* An unrelated block size scores zero. */
  char other[RF_HASH_OUT_CAPACITY + 16];
  std::snprintf(other, sizeof(other), "%lu:%s:%s", block * 3u + 1u, s1.c_str(),
                s2.c_str());
  CHECK_EQ_INT(rf_compare(h.c_str(), other), 0);
}

void test_edge_cases() {
  g_case = "edge cases";
  char out[RF_HASH_OUT_CAPACITY + 16];

  /* Empty input. */
  CHECK_EQ_INT(rf_hash_buffer(nullptr, 0, out, sizeof(out)), RF_OK);
  CHECK_EQ_INT(std::strlen(out) > 0, 1);

  /* An input smaller than the rolling window. */
  const std::uint8_t tiny[3] = {1, 2, 3};
  CHECK_EQ_INT(rf_hash_buffer(tiny, sizeof(tiny), out, sizeof(out)), RF_OK);

  /* A buffer that is not NUL terminated must be handled. */
  std::vector<std::uint8_t> binary(1024, 0x00);
  binary[500] = 0xFF;
  CHECK_EQ_INT(rf_hash_buffer(binary.data(), binary.size(), out, sizeof(out)),
               RF_OK);

  /* All zero bytes. */
  std::vector<std::uint8_t> zeros(100000, 0x00);
  const std::string hz = hash_buffer(zeros);
  CHECK(!hz.empty());
  std::printf("  all-zero buffer           -> %s\n", hz.c_str());
  std::string bs;
  std::string s1;
  std::string s2;
  split_hash(hz, bs, s1, s2);
  CHECK(!bs.empty());
  /* The signature must not be empty, even for uniform input. */
  CHECK(!s1.empty());

  /* An all zero buffer and a different all zero buffer of another size
   * must not be reported as identical. */
  std::vector<std::uint8_t> zeros2(200000, 0x00);
  const std::string hz2 = hash_buffer(zeros2);
  CHECK(rf_compare(hz.c_str(), hz2.c_str()) < 100);

  /* A too small output buffer is reported, not written over. */
  char tiny_out[4];
  std::memset(tiny_out, 'X', sizeof(tiny_out));
  CHECK_EQ_INT(rf_hash_buffer(tiny, sizeof(tiny), tiny_out,
                              sizeof(tiny_out)),
               RF_ERR_CAPACITY);

  /* NULL pointers are refused. */
  CHECK_EQ_INT(rf_hash_buffer(nullptr, 0, nullptr, 10), RF_ERR_NULL);
  CHECK_EQ_INT(rf_hash_buffer(tiny, 3, nullptr, 10), RF_ERR_NULL);
  CHECK_EQ_INT(rf_hash_file(nullptr, out, sizeof(out)), RF_ERR_NULL);
  CHECK_EQ_INT(rf_compare(nullptr, "3::"), RF_ERR_NULL);
  CHECK_EQ_INT(rf_compare("3::", nullptr), RF_ERR_NULL);
}

void test_large_file() {
  g_case = "large file";
  const char* path = "rak_fuzzy_test_big.bin";
  const std::size_t kSize = 100u * 1024u * 1024u;

  {
    FILE* f = std::fopen(path, "wb");
    CHECK(f != nullptr);
    if (f == nullptr) {
      return;
    }
    std::vector<std::uint8_t> block(1024u * 1024u);
    Rng rng(20240607);
    for (std::size_t written = 0; written < kSize; written += block.size()) {
      rng.fill(block.data(), block.size());
      std::fwrite(block.data(), 1, block.size(), f);
    }
    std::fclose(f);
  }

  const std::size_t before = peak_memory_bytes();
  std::string out(RF_HASH_OUT_CAPACITY + 16, '\0');
  const std::uint64_t started = now_micros();
  const int rc = rf_hash_file(path, &out[0], out.size());
  const std::uint64_t elapsed = now_micros() - started;
  const std::size_t after = peak_memory_bytes();
  out.resize(std::strlen(out.c_str()));

  CHECK_EQ_INT(rc, RF_OK);
  CHECK(!out.empty());
  std::printf("  100 MiB file              -> %s\n", out.c_str());
  std::printf("  file throughput           -> %.1f MiB/s (%.0f MB/s)\n",
              static_cast<double>(kSize) / 1048576.0 /
                  (static_cast<double>(elapsed) / 1000000.0),
              static_cast<double>(kSize) / 1048576.0 /
                      (static_cast<double>(elapsed) / 1000000.0) * 1.048576);
  std::printf("  peak working set          -> %.2f MiB (delta %.2f MiB)\n",
              static_cast<double>(after) / (1024.0 * 1024.0),
              static_cast<double>(after - before) / (1024.0 * 1024.0));
  /* The file is hashed in chunks, so the memory use must stay far below
   * the size of the file. */
  CHECK(after < kSize);

  /* Hashing the same file twice gives the same result. */
  std::string out2(RF_HASH_OUT_CAPACITY + 16, '\0');
  CHECK_EQ_INT(rf_hash_file(path, &out2[0], out2.size()), RF_OK);
  out2.resize(std::strlen(out2.c_str()));
  CHECK_EQ_INT(out == out2, 1);

  std::remove(path);
}

void test_benchmark() {
  g_case = "benchmark";
  const std::size_t kSize = 64u * 1024u * 1024u;
  Rng rng(555);
  std::vector<std::uint8_t> data(kSize);
  rng.fill(data.data(), data.size());

  std::string out(RF_HASH_OUT_CAPACITY + 16, '\0');
  /* warm up */
  rf_hash_buffer(data.data(), data.size(), &out[0], out.size());

  const int rounds = 5;
  const std::uint64_t start = now_micros();
  for (int i = 0; i < rounds; ++i) {
    rf_hash_buffer(data.data(), data.size(), &out[0], out.size());
  }
  const std::uint64_t elapsed = now_micros() - start;
  const double mib = (static_cast<double>(kSize) * rounds) / (1024.0 * 1024.0);
  const double seconds = static_cast<double>(elapsed) / 1000000.0;
  std::printf("  CTPH throughput           -> %.1f MiB/s (%.0f MB/s)\n",
              mib / seconds, mib / seconds * 1.048576);
  CHECK(seconds > 0.0);
}

} /* namespace */

int main(int argc, char** argv) {
  bool bench = false;
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--bench") == 0) {
      bench = true;
    }
  }

  std::printf("rak-fuzzy CTPH tests\n");
  test_format_and_determinism();
  test_identical_and_unrelated();
  test_mutation_scores();
  test_inserted_block();
  test_block_size_neighbours();
  test_edge_cases();
  test_large_file();
  if (bench) {
    test_benchmark();
  }

  std::printf("%d checks, %d failures\n", g_checks, g_failures);
  return g_failures == 0 ? 0 : 1;
}
