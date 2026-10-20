/*
 * rak-fuzzy - internal CTPH (context triggered piecewise hashing) interface.
 *
 * This header is internal to the library. The exported surface lives in
 * include/rak_fuzzy.h and is plain C.
 */

#ifndef RKF_CTPH_HPP
#define RKF_CTPH_HPP

#include <cstddef>
#include <cstdint>
#include <string>

namespace rkf {

/* Longest signature produced for one block size (base64 characters). */
constexpr std::size_t kMaxSigChars = 64;

/* Smallest block size the algorithm will use. */
constexpr std::uint32_t kMinBlockSize = 3;

/* Size of the rolling hash window, in bytes. */
constexpr std::size_t kRollWindow = 7;

/* Two signatures must share at least this many characters to be comparable. */
constexpr std::size_t kMinCommonSubstring = 7;

/* Result of hashing a buffer or a file. */
struct HashResult {
  std::uint32_t block_size = 0; /* reported block size                */
  std::string sig1;             /* signature at  block_size            */
  std::string sig2;             /* signature at 2 * block_size         */
};

/* A hash that has been split into its three components. */
struct ParsedHash {
  std::uint32_t block_size = 0;
  std::string sig1;
  std::string sig2;
};

/*
 * Streaming CTPH engine.
 *
 * The engine keeps a fixed amount of state, so it can be fed a file of any
 * size in arbitrary chunks. It emits one base64 character per chunk, for two
 * granularities at once: the reported block size and twice that.
 */
class CtpHasher {
 public:
  /*
   * `block_size` must be >= kMinBlockSize.
   *
   * `fixed_mode` selects the fallback chunking used for degenerate inputs
   * (for example a file of all zero bytes, where every rolling window is
   * identical and the modular boundary condition can never fire). In fixed
   * mode a chunk boundary is placed every `block_size` bytes regardless of
   * the data.
   */
  explicit CtpHasher(std::uint32_t block_size, bool fixed_mode = false);

  /* Feed more bytes. */
  void update(const std::uint8_t* data, std::size_t len);

  /* Number of complete chunks emitted at the reported block size. */
  std::uint64_t chunks() const { return chunks0_; }

  /* True if one of the signatures outgrew kMaxSigChars. */
  bool overflowed() const { return overflow_; }

  /* Produce the final hash. Must be called exactly once. */
  HashResult finish();

 private:
  void boundary(int level);
  void emit(int level, std::uint64_t run_hash, std::uint64_t chunk_index);
  void update_fixed(const std::uint8_t* data, std::size_t len);

  std::uint32_t bs_;      /* reported block size                     */
  std::uint32_t mod_;     /* 2 * bs_, the modulus of the boundary test */
  std::uint64_t magic_;   /* reciprocal of mod_ for fast_mod          */
  std::uint32_t rolling_; /* rolling window hash                     */
  bool started_ = false;  /* has the first byte been seen?            */
  std::uint8_t window_[kRollWindow] = {0, 0, 0, 0, 0, 0, 0};
  int wpos_ = 0;
  int wfill_ = 0;

  std::uint64_t run0_ = 0; /* running hash of the current chunk, level 0 */
  std::uint64_t run1_ = 0; /* running hash of the current chunk, level 1 */
  bool pending0_ = false;  /* bytes seen since the last level 0 boundary  */
  bool pending1_ = false;

  std::uint64_t chunks0_ = 0;
  std::uint64_t chunks1_ = 0;
  std::uint64_t bytes_ = 0;

  std::string sig0_;
  std::string sig1_;
  bool overflow_ = false;
  bool fixed_ = false;
};

/* Block size the algorithm starts from for an input of `len` bytes. */
std::uint32_t initial_block_size(std::uint64_t len);

/* Hash an in-memory buffer. `data` may be null when `len` is 0. */
HashResult hash_buffer(const std::uint8_t* data, std::size_t len);

/* Hash a file, streaming it in fixed size chunks. */
bool hash_file(const char* path, HashResult& out);

/* Split "bs:sig1:sig2" into its components. Returns false when malformed. */
bool parse_hash(const char* text, ParsedHash& out);

/* Same, but for a hash that is not NUL terminated (a range). */
bool parse_hash(const char* begin, const char* end, ParsedHash& out);

/* Render a hash back into "bs:sig1:sig2". */
std::string format_hash(const HashResult& h);

/* Similarity of two parsed hashes, 0..100. */
int compare_parsed(const ParsedHash& a, const ParsedHash& b);

/* Similarity of two hash strings, 0..100 (negative on malformed input). */
int compare_hash_text(const char* a, const char* b);

/* Collapse runs of more than three identical characters to three. */
std::string collapse_runs(const std::string& s);

/*
 * Score one pair of signatures.
 *
 * `confidence_pct` scales the result down for very small block sizes; it is
 * expressed in percent (100 = no scaling). An exact match always scores 100.
 */
int score_signature_pair(const std::string& s1, const std::string& s2,
                         int confidence_pct);

} /* namespace rkf */

#endif /* RKF_CTPH_HPP */
