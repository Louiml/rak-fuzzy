/*
 * rak-fuzzy - CTPH (context triggered piecewise hashing) core.
 *
 * The idea, in one paragraph:
 *
 *   A file is cut into chunks whose boundaries are decided by *data*, not by
 *   position. A rolling hash over a 7 byte window is evaluated at every byte
 *   and a chunk boundary is placed whenever the hash hits a fixed residue
 *   modulo the block size. Because the window is short, a single modified
 *   byte only perturbs the chunking for a few bytes afterwards: the rolling
 *   hash resynchronises and the original chunk boundaries reappear. That is
 *   what makes the resulting signature survive small edits, insertions and
 *   deletions instead of collapsing into noise.
 *
 *   Every chunk contributes one base64 character, derived from a running
 *   FNV-1a hash of the chunk's bytes. Two signatures are then compared with a
 *   weighted edit distance.
 *
 * Everything here is integer arithmetic on fixed width types, so the output
 * is bit identical on every platform, independent of endianness and of
 * whether `char` is signed.
 */

#include "ctph.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <vector>

namespace rkf {
namespace {

/* Base64 alphabet used for the signature characters. */
constexpr char kB64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* FNV-1a 32 bit prime, used for the rolling window hash. */
constexpr std::uint32_t kRollPrime = 0x01000193u;

/* FNV-1a 64 bit prime and offset basis, used for the per chunk hash. */
constexpr std::uint64_t kFnvPrime = 0x100000001b3ull;
constexpr std::uint64_t kFnvOffset = 0xcbf29ce484222325ull;

/* Compile time exponentiation modulo 2^32 (unsigned overflow is defined). */
constexpr std::uint32_t pow32(std::uint32_t base, int exponent) {
  std::uint32_t result = 1;
  for (int i = 0; i < exponent; ++i) {
    result *= base;
  }
  return result;
}

/* kRollPrime^7: the weight of the byte that leaves the window. */
constexpr std::uint32_t kRollPrimePow7 = pow32(kRollPrime, 7);

/*
 * Reciprocal based remainder.
 *
 * For a divisor d and a 32 bit numerator n,
 *
 *     r = high64( (low64(m * n)) * d )     with  m = floor(2^64 / d) + 1
 *
 * is exactly n % d (Lemire, "Faster Remainder by Direct Computation"). It
 * replaces a hardware division with two multiplies, which matters because the
 * boundary test runs once per input byte.
 */
inline std::uint32_t fast_mod(std::uint32_t n, std::uint32_t d,
                              std::uint64_t magic) {
#if defined(__SIZEOF_INT128__)
  const std::uint64_t low = magic * static_cast<std::uint64_t>(n);
  return static_cast<std::uint32_t>(
      (static_cast<unsigned __int128>(low) * static_cast<std::uint64_t>(d)) >> 64);
#else
  (void)magic;
  return n % d;
#endif
}

inline bool is_b64(char c) {
  const unsigned char u = static_cast<unsigned char>(c);
  return (u >= 'A' && u <= 'Z') || (u >= 'a' && u <= 'z') ||
         (u >= '0' && u <= '9') || u == '+' || u == '/';
}

/* Length of the longest common substring of two strings. */
std::size_t longest_common_substring(const std::string& a, const std::string& b) {
  if (a.empty() || b.empty()) {
    return 0;
  }
  const std::size_t n = a.size();
  const std::size_t m = b.size();
  std::vector<int> prev(m + 1, 0);
  std::vector<int> cur(m + 1, 0);
  std::size_t best = 0;
  for (std::size_t i = 1; i <= n; ++i) {
    for (std::size_t j = 1; j <= m; ++j) {
      if (a[i - 1] == b[j - 1]) {
        cur[j] = prev[j - 1] + 1;
        if (static_cast<std::size_t>(cur[j]) > best) {
          best = static_cast<std::size_t>(cur[j]);
        }
      } else {
        cur[j] = 0;
      }
    }
    prev.swap(cur);
  }
  return best;
}

/*
 * Weighted edit distance: insertion and deletion cost 1, substitution costs
 * 2. Using 2 for a substitution makes the metric favour aligned matches
 * over a substitution plus a shift, which behaves better on signatures that
 * contain runs of similar characters.
 */
int weighted_edit_distance(const std::string& a, const std::string& b) {
  const std::size_t n = a.size();
  const std::size_t m = b.size();
  std::vector<int> prev(m + 1, 0);
  std::vector<int> cur(m + 1, 0);
  for (std::size_t j = 0; j <= m; ++j) {
    prev[j] = static_cast<int>(j);
  }
  for (std::size_t i = 1; i <= n; ++i) {
    cur[0] = static_cast<int>(i);
    for (std::size_t j = 1; j <= m; ++j) {
      const int sub = prev[j - 1] + (a[i - 1] == b[j - 1] ? 0 : 2);
      const int del = prev[j] + 1;
      const int ins = cur[j - 1] + 1;
      cur[j] = std::min(sub, std::min(del, ins));
    }
    prev.swap(cur);
  }
  return prev[m];
}

} /* namespace */

/* ------------------------------------------------------------------ */
/* CtpHasher                                                            */
/* ------------------------------------------------------------------ */

CtpHasher::CtpHasher(std::uint32_t block_size, bool fixed_mode)
    : bs_(block_size < kMinBlockSize ? kMinBlockSize : block_size),
      fixed_(fixed_mode) {
  mod_ = bs_ * 2u;
  magic_ = 0xFFFFFFFFFFFFFFFFull / static_cast<std::uint64_t>(mod_) + 1ull;
  run0_ = kFnvOffset;
  run1_ = kFnvOffset;
  sig0_.reserve(kMaxSigChars);
  sig1_.reserve(kMaxSigChars);
}

void CtpHasher::emit(int level, std::uint64_t run_hash,
                     std::uint64_t chunk_index) {
  std::string& sig = (level == 0) ? sig0_ : sig1_;
  if (sig.size() >= kMaxSigChars) {
    overflow_ = true;
    return;
  }
  /*
   * Normal mode: the character only depends on the content of the chunk.
   * Fixed (degenerate input) mode: the chunk index is folded in as well, so
   * that two uniform files of different length still produce different
   * signatures instead of one endless run of the same character.
   */
  std::uint64_t index = 0;
  if (fixed_) {
    index = chunk_index;
  }
  const std::uint64_t mixed = (run_hash >> 58) + index;
  sig.push_back(kB64[mixed & 63u]);
}

void CtpHasher::boundary(int level) {
  if (level == 0) {
    emit(0, run0_, chunks0_);
    run0_ = kFnvOffset;
    pending0_ = false;
    ++chunks0_;
  } else {
    emit(1, run1_, chunks1_);
    run1_ = kFnvOffset;
    pending1_ = false;
    ++chunks1_;
  }
}

void CtpHasher::update(const std::uint8_t* data, std::size_t len) {
  if (data == nullptr || len == 0) {
    return;
  }
  if (fixed_) {
    update_fixed(data, len);
    return;
  }

  /*
   * The whole state is copied into locals for the duration of the loop.
   * Otherwise the compiler has to assume that the input bytes may alias the
   * member variables (a `char` array may alias anything) and reloads the
   * whole state after every single byte, which costs more than twice the
   * hashing itself.
   */
  std::uint32_t rolling = rolling_;
  std::uint64_t run0 = run0_;
  std::uint64_t run1 = run1_;
  std::uint64_t chunks0 = chunks0_;
  std::uint64_t chunks1 = chunks1_;
  bool pending0 = pending0_;
  bool pending1 = pending1_;
  bool overflow = overflow_;

  std::uint8_t window[kRollWindow];
  for (std::size_t i = 0; i < kRollWindow; ++i) {
    window[i] = window_[i];
  }
  int wpos = wpos_;
  int wfill = wfill_;

  char out0[kMaxSigChars];
  char out1[kMaxSigChars];
  std::size_t n0 = sig0_.size();
  std::size_t n1 = sig1_.size();
  for (std::size_t i = 0; i < n0; ++i) {
    out0[i] = sig0_[i];
  }
  for (std::size_t i = 0; i < n1; ++i) {
    out1[i] = sig1_[i];
  }

  const std::uint32_t bs = bs_;
  const std::uint32_t mod = mod_;
  const std::uint64_t magic = magic_;

  /*
   * The first byte seeds the rolling hash. Starting with the first byte
   * itself (instead of zero) means that no history term survives in the
   * hash, so it stays a pure function of the current window.
   */
  if (!started_) {
    const std::uint32_t c = data[0];
    rolling = c + 1u;
    started_ = true;
    window[0] = static_cast<std::uint8_t>(c);
    wpos = 1;
    wfill = 1;
    run0 = (run0 ^ c) * kFnvPrime;
    run1 = (run1 ^ c) * kFnvPrime;
    pending0 = true;
    pending1 = true;
    ++data;
    --len;
  }

  for (std::size_t i = 0; i < len; ++i) {
    const std::uint32_t c = data[i];

    /*
     * Rolling window hash.
     *
     * The window is a polynomial over the last seven bytes where the newest
     * byte has weight 1 and the oldest has weight P^6. Updating it is
     *
     *     h = h * P + value(new) - value(old) * P^7
     *
     * with value(x) = x + 1. The "+1" keeps a window of zero bytes from
     * hashing to zero, and because the hash is seeded with the first byte
     * no history term survives: the hash is a pure function of the current
     * window, which is what lets it resynchronise after an edit.
     */
    const std::uint32_t added = c + 1u;
    const std::uint32_t removed =
        (wfill == static_cast<int>(kRollWindow))
            ? static_cast<std::uint32_t>(window[wpos]) + 1u
            : 0u;
    rolling = rolling * kRollPrime + added - removed * kRollPrimePow7;
    window[wpos] = static_cast<std::uint8_t>(c);
    ++wpos;
    if (wpos == static_cast<int>(kRollWindow)) {
      wpos = 0;
    }
    if (wfill < static_cast<int>(kRollWindow)) {
      ++wfill;
    }

    /* Running hash of the bytes belonging to the current chunk. */
    run0 = (run0 ^ c) * kFnvPrime;
    run1 = (run1 ^ c) * kFnvPrime;
    pending0 = true;
    pending1 = true;

    /*
     * Boundary detection.
     *
     * A level 0 boundary requires rolling % bs == bs - 1 and a level 1
     * boundary requires rolling % (2*bs) == 2*bs - 1. Computing
     * r = rolling % (2*bs) once is enough: because bs divides 2*bs,
     * rolling % bs == r % bs, which is bs - 1 exactly when r is bs - 1 or
     * 2*bs - 1. A single remainder per byte therefore yields both tests.
     */
    const std::uint32_t r = fast_mod(rolling, mod, magic);
    if (r == mod - 1u) {
      if (n0 < kMaxSigChars) {
        out0[n0++] = kB64[(run0 >> 58) & 63u];
      } else {
        overflow = true;
      }
      run0 = kFnvOffset;
      pending0 = false;
      ++chunks0;
      if (n1 < kMaxSigChars) {
        out1[n1++] = kB64[(run1 >> 58) & 63u];
      } else {
        overflow = true;
      }
      run1 = kFnvOffset;
      pending1 = false;
      ++chunks1;
    } else if (r == bs - 1u) {
      if (n0 < kMaxSigChars) {
        out0[n0++] = kB64[(run0 >> 58) & 63u];
      } else {
        overflow = true;
      }
      run0 = kFnvOffset;
      pending0 = false;
      ++chunks0;
    }
  }

  rolling_ = rolling;
  run0_ = run0;
  run1_ = run1;
  chunks0_ = chunks0;
  chunks1_ = chunks1;
  pending0_ = pending0;
  pending1_ = pending1;
  overflow_ = overflow;
  for (std::size_t i = 0; i < kRollWindow; ++i) {
    window_[i] = window[i];
  }
  wpos_ = wpos;
  wfill_ = wfill;
  sig0_.assign(out0, n0);
  sig1_.assign(out1, n1);
}

/*
 * Fallback chunking for degenerate input: boundaries every bs (level 0) and
 * every 2*bs (level 1) bytes, counted from the start of the stream.
 */
void CtpHasher::update_fixed(const std::uint8_t* data, std::size_t len) {
  for (std::size_t i = 0; i < len; ++i) {
    const std::uint8_t c = data[i];
    ++bytes_;
    run0_ = (run0_ ^ c) * kFnvPrime;
    run1_ = (run1_ ^ c) * kFnvPrime;
    pending0_ = true;
    pending1_ = true;
    if (bytes_ % bs_ == 0) {
      boundary(0);
    }
    if (bytes_ % mod_ == 0) {
      boundary(1);
    }
  }
}

HashResult CtpHasher::finish() {
  /*
   * The trailing partial chunk is hashed as well. Without it, appending a
   * few bytes to a file would leave the signature completely unchanged,
   * which hides the most common kind of tampering.
   */
  if (pending0_) {
    emit(0, run0_, chunks0_);
    pending0_ = false;
  }
  if (pending1_) {
    emit(1, run1_, chunks1_);
    pending1_ = false;
  }
  HashResult out;
  out.block_size = bs_;
  out.sig1 = sig0_;
  out.sig2 = sig1_;
  return out;
}

/* ------------------------------------------------------------------ */
/* Drivers                                                              */
/* ------------------------------------------------------------------ */

std::uint32_t initial_block_size(std::uint64_t len) {
  /*
   * Aim for roughly 48 chunks. The signature budget is 64 characters, and a
   * chunk count that is a good deal smaller than the budget leaves room for
   * the random fluctuation of the chunk boundaries; the caller doubles the
   * block size and retries if a signature still outgrows the budget. The
   * block size sequence is 3, 6, 12, 24, ... as required by the format.
   */
  const std::uint64_t target = (len + 47u) / 48u;
  std::uint32_t bs = kMinBlockSize;
  while (static_cast<std::uint64_t>(bs) < target &&
         bs < (1u << 30)) {
    bs *= 2u;
  }
  return bs;
}

namespace {

/* Number of times the hashing pass is retried with a larger block size. */
constexpr int kMaxAttempts = 12;

} /* namespace */

HashResult hash_buffer(const std::uint8_t* data, std::size_t len) {
  std::uint32_t bs = initial_block_size(static_cast<std::uint64_t>(len));
  HashResult last;
  for (int attempt = 0; attempt < kMaxAttempts; ++attempt) {
    CtpHasher hasher(bs);
    hasher.update(data, len);
    last = hasher.finish();
    if (!hasher.overflowed()) {
      /*
       * Not a single boundary was placed: every rolling window was
       * identical, which happens for uniform data such as a file of zero
       * bytes. Fall back to fixed size chunking so the file still gets a
       * meaningful, length sensitive signature.
       */
      if (hasher.chunks() == 0 && len > 0) {
        CtpHasher fixed(bs, true);
        fixed.update(data, len);
        return fixed.finish();
      }
      return last;
    }
    bs *= 2u;
  }
  /* Extremely unlikely; return the (truncated) last attempt. */
  return last;
}

bool hash_file(const char* path, HashResult& out) {
  if (path == nullptr) {
    return false;
  }
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return false;
  }
  in.seekg(0, std::ios::end);
  const std::streamoff size = in.tellg();
  in.seekg(0, std::ios::beg);
  if (size < 0) {
    return false;
  }

  std::uint32_t bs = initial_block_size(static_cast<std::uint64_t>(size));
  std::vector<char> buffer(64u * 1024u);
  HashResult last;
  for (int attempt = 0; attempt < kMaxAttempts; ++attempt) {
    CtpHasher hasher(bs);
    in.clear();
    in.seekg(0, std::ios::beg);
    bool ok = true;
    while (in.read(buffer.data(), static_cast<std::streamsize>(buffer.size())) ||
           in.gcount() > 0) {
      const std::streamsize got = in.gcount();
      if (got > 0) {
        hasher.update(reinterpret_cast<const std::uint8_t*>(buffer.data()),
                      static_cast<std::size_t>(got));
      }
      if (!in) {
        if (in.eof()) {
          break;
        }
        ok = false;
        break;
      }
    }
    if (!ok) {
      return false;
    }
    last = hasher.finish();
    if (!hasher.overflowed()) {
      if (hasher.chunks() == 0 && size > 0) {
        CtpHasher fixed(bs, true);
        in.clear();
        in.seekg(0, std::ios::beg);
        while (in.read(buffer.data(),
                       static_cast<std::streamsize>(buffer.size())) ||
               in.gcount() > 0) {
          const std::streamsize got = in.gcount();
          if (got > 0) {
            fixed.update(
                reinterpret_cast<const std::uint8_t*>(buffer.data()),
                static_cast<std::size_t>(got));
          }
          if (!in) {
            if (in.eof()) {
              break;
            }
            return false;
          }
        }
        out = fixed.finish();
        return true;
      }
      out = last;
      return true;
    }
    bs *= 2u;
  }
  out = last;
  return true;
}

/* ------------------------------------------------------------------ */
/* Parsing and formatting                                               */
/* ------------------------------------------------------------------ */

bool parse_hash(const char* text, ParsedHash& out) {
  if (text == nullptr) {
    return false;
  }
  return parse_hash(text, text + std::strlen(text), out);
}

bool parse_hash(const char* begin, const char* end, ParsedHash& out) {
  if (begin == nullptr || end == nullptr || end < begin) {
    return false;
  }
  const char* p = begin;
  if (p == end || *p < '0' || *p > '9') {
    return false;
  }
  std::uint64_t bs = 0;
  int digits = 0;
  while (p != end && *p >= '0' && *p <= '9') {
    bs = bs * 10u + static_cast<std::uint64_t>(*p - '0');
    if (bs > 0x7FFFFFFFull) {
      return false; /* absurd block size */
    }
    ++p;
    if (++digits > 10) {
      return false;
    }
  }
  if (p == end || *p != ':') {
    return false;
  }
  ++p;
  const char* s1_begin = p;
  while (p != end && *p != ':') {
    if (!is_b64(*p)) {
      return false;
    }
    ++p;
  }
  if (p == end || *p != ':') {
    return false;
  }
  const char* s1_end = p;
  ++p;
  const char* s2_begin = p;
  while (p != end) {
    if (!is_b64(*p)) {
      return false;
    }
    ++p;
  }
  const char* s2_end = p;

  if (bs == 0) {
    return false;
  }
  if (static_cast<std::size_t>(s1_end - s1_begin) > kMaxSigChars) {
    return false;
  }
  if (static_cast<std::size_t>(s2_end - s2_begin) > kMaxSigChars) {
    return false;
  }
  out.block_size = static_cast<std::uint32_t>(bs);
  out.sig1.assign(s1_begin, s1_end);
  out.sig2.assign(s2_begin, s2_end);
  return true;
}

std::string format_hash(const HashResult& h) {
  std::string out = std::to_string(h.block_size);
  out.push_back(':');
  out.append(h.sig1);
  out.push_back(':');
  out.append(h.sig2);
  return out;
}

/* ------------------------------------------------------------------ */
/* Comparison                                                           */
/* ------------------------------------------------------------------ */

std::string collapse_runs(const std::string& s) {
  std::string out;
  out.reserve(s.size());
  for (char c : s) {
    const std::size_t n = out.size();
    if (n >= 3 && out[n - 1] == c && out[n - 2] == c && out[n - 3] == c) {
      continue; /* keep at most three identical characters in a row */
    }
    out.push_back(c);
  }
  return out;
}

int score_signature_pair(const std::string& s1, const std::string& s2,
                         int confidence_pct) {
  const std::string a = collapse_runs(s1);
  const std::string b = collapse_runs(s2);
  if (a.empty() || b.empty()) {
    return 0;
  }
  if (a == b) {
    /* An exact match is conclusive, no matter how small the block size. */
    return 100;
  }
  if (longest_common_substring(a, b) < kMinCommonSubstring) {
    return 0;
  }
  const std::size_t length = std::max(a.size(), b.size());
  const int distance = weighted_edit_distance(a, b);
  if (distance <= 0 || distance >= static_cast<int>(length)) {
    return 0;
  }
  int base = static_cast<int>((static_cast<std::int64_t>(length - distance) *
                                100) /
                               static_cast<std::int64_t>(length));
  if (base > 100) {
    base = 100;
  }
  if (confidence_pct >= 100) {
    return base;
  }
  if (confidence_pct < 0) {
    confidence_pct = 0;
  }
  return static_cast<int>((static_cast<std::int64_t>(base) * confidence_pct) /
                          100);
}

int compare_parsed(const ParsedHash& a, const ParsedHash& b) {
  if (a.block_size == 0 || b.block_size == 0) {
    return 0;
  }
  /*
   * Confidence factor: signatures derived from a very small block size come
   * from very short files, where a high score means much less than it does
   * for a multi megabyte sample.
   */
  const std::uint32_t finest =
      std::min(a.block_size, b.block_size);
  int confidence = static_cast<int>(static_cast<std::uint64_t>(finest) * 100u / 6u);
  if (confidence > 100) {
    confidence = 100;
  }

  const std::uint64_t a1 = a.block_size;
  const std::uint64_t b1 = b.block_size;
  int best = 0;
  if (a1 == b1) {
    best = std::max(best, score_signature_pair(a.sig1, b.sig1, confidence));
    best = std::max(best, score_signature_pair(a.sig2, b.sig2, confidence));
  } else if (b1 == a1 * 2u) {
    /* The finer hash contributes its coarse signature, the coarser one its
     * fine signature: both describe the same chunk size. */
    best = score_signature_pair(a.sig2, b.sig1, confidence);
  } else if (a1 == b1 * 2u) {
    best = score_signature_pair(a.sig1, b.sig2, confidence);
  }
  return best;
}

int compare_hash_text(const char* a, const char* b) {
  ParsedHash pa;
  ParsedHash pb;
  if (!parse_hash(a, pa) || !parse_hash(b, pb)) {
    return -4; /* RF_ERR_FORMAT */
  }
  return compare_parsed(pa, pb);
}

} /* namespace rkf */
