/*
 * rak-fuzzy - single linkage clustering of CTPH hashes.
 *
 * Comparing every pair of N hashes costs O(N^2) comparisons, which is far
 * too slow for a directory of a few thousand samples. The implementation
 * therefore uses an inverted index:
 *
 *   * Every signature is split into overlapping 7 character substrings
 *     ("grams"). A gram is encoded in 42 bits, because the signature
 *     alphabet has 64 symbols and 7 * 6 = 42.
 *   * The index maps (absolute block size, gram) to the list of signatures
 *     that contain it.
 *   * Two hashes can only reach a non zero similarity score when their
 *     matched signatures share a common substring of at least seven
 *     characters, so they must share a gram. Hashes that share no gram are
 *     therefore never scored, and the pair count drops from O(N^2) to
 *     "number of hashes that actually look alike".
 *
 * The "absolute block size" of a signature is the chunk size it was
 * computed with: `block size` for the first signature of a hash and
 * `2 * block size` for the second one. Two signatures can only be compared
 * when their absolute block sizes are equal, which is exactly the pairing
 * rule used by the similarity function (equal block sizes, or one double
 * the other). Grouping the index by absolute block size therefore makes
 * the candidate pairs automatically compatible.
 */

#include "cluster.hpp"

#include <algorithm>
#include <string>
#include <unordered_map>
#include <vector>

namespace rkf {
namespace {

/*
 * Upper bound on the number of similarity computations performed for a
 * single gram. Without it a corpus of thousands of near identical files
 * would make one posting list quadratic in size. Reaching the limit only
 * costs precision, never correctness of the program.
 */
constexpr std::size_t kMaxComparisonsPerGram = 50000;

/* Position of a character in the base64 alphabet, or -1 when invalid. */
int b64_value(char c) {
  const unsigned char u = static_cast<unsigned char>(c);
  if (u >= 'A' && u <= 'Z') {
    return u - 'A';
  }
  if (u >= 'a' && u <= 'z') {
    return u - 'a' + 26;
  }
  if (u >= '0' && u <= '9') {
    return u - '0' + 52;
  }
  if (u == '+') {
    return 62;
  }
  if (u == '/') {
    return 63;
  }
  return -1;
}

/* One entry of an inverted index posting list. */
struct Entry {
  std::uint32_t hash_index; /* which hash the signature belongs to  */
  std::uint8_t level;       /* 0 = first signature, 1 = second one   */
  std::uint32_t abs_bs;     /* absolute block size of the signature  */
};

/* Union-find with path compression and union by size. */
class DisjointSet {
 public:
  explicit DisjointSet(std::size_t n) : parent_(n), size_(n, 1) {
    for (std::size_t i = 0; i < n; ++i) {
      parent_[i] = static_cast<std::uint32_t>(i);
    }
  }

  std::uint32_t find(std::uint32_t x) {
    while (parent_[x] != x) {
      parent_[x] = parent_[parent_[x]];
      x = parent_[x];
    }
    return x;
  }

  void unite(std::uint32_t a, std::uint32_t b) {
    std::uint32_t ra = find(a);
    std::uint32_t rb = find(b);
    if (ra == rb) {
      return;
    }
    if (size_[ra] < size_[rb]) {
      std::swap(ra, rb);
    }
    parent_[rb] = ra;
    size_[ra] += size_[rb];
  }

 private:
  std::vector<std::uint32_t> parent_;
  std::vector<std::uint32_t> size_;
};

} /* namespace */

int cluster_hashes(const ParsedHash* hashes, std::size_t n, int threshold,
                   std::int32_t* out) {
  if (out == nullptr) {
    return -1; /* RF_ERR_NULL */
  }
  if (n == 0) {
    return 0;
  }
  if (hashes == nullptr) {
    return -1;
  }
  if (threshold < 0 || threshold > 100) {
    return -5; /* RF_ERR_RANGE */
  }

  /*
   * A threshold of zero means every pair of hashes is related, so everything
   * collapses into a single cluster. Handling it here avoids the O(N^2)
   * scan that the general path would need.
   */
  if (threshold == 0) {
    for (std::size_t i = 0; i < n; ++i) {
      out[i] = 0;
    }
    return 0;
  }

  /* Precompute the collapsed signatures and the absolute block sizes. */
  std::vector<std::string> collapsed[2];
  std::vector<std::uint32_t> abs_bs[2];
  for (int level = 0; level < 2; ++level) {
    collapsed[level].resize(n);
    abs_bs[level].resize(n);
  }
  for (std::size_t i = 0; i < n; ++i) {
    const std::uint64_t bs = hashes[i].block_size;
    collapsed[0][i] = collapse_runs(hashes[i].sig1);
    collapsed[1][i] = collapse_runs(hashes[i].sig2);
    abs_bs[0][i] = static_cast<std::uint32_t>(bs);
    abs_bs[1][i] = static_cast<std::uint32_t>(bs * 2u);
  }

  /*
   * Inverted index: absolute block size -> gram -> posting list.
   *
   * Signatures shorter than the minimum common substring length cannot
   * contain a gram, so they are indexed by their whole (collapsed) text
   * instead. That keeps the "identical signatures score 100" rule working
   * for very short signatures as well.
   */
  std::unordered_map<std::uint32_t,
                     std::unordered_map<std::uint64_t, std::vector<Entry>>>
      gram_index;
  std::unordered_map<std::uint32_t,
                     std::unordered_map<std::string, std::vector<Entry>>>
      short_index;

  for (std::size_t i = 0; i < n; ++i) {
    for (int level = 0; level < 2; ++level) {
      const std::string& sig = collapsed[level][i];
      if (sig.empty()) {
        continue;
      }
      Entry entry{static_cast<std::uint32_t>(i),
                  static_cast<std::uint8_t>(level), abs_bs[level][i]};
      if (sig.size() < kMinCommonSubstring) {
        short_index[abs_bs[level][i]][sig].push_back(entry);
        continue;
      }
      std::uint64_t gram = 0;
      for (std::size_t p = 0; p < sig.size(); ++p) {
        gram = ((gram << 6) | static_cast<std::uint64_t>(b64_value(sig[p]) &
                                                          63)) &
               0x3FFFFFFFFFFFFFull;
        if (p + 1 >= kMinCommonSubstring) {
          gram_index[abs_bs[level][i]][gram].push_back(entry);
        }
      }
    }
  }

  DisjointSet dsu(n);

  /* Score a candidate pair of signatures. */
  auto score_entries = [&](const Entry& a, const Entry& b) -> int {
    const std::uint32_t finest = std::min(hashes[a.hash_index].block_size,
                                          hashes[b.hash_index].block_size);
    int confidence =
        static_cast<int>(static_cast<std::uint64_t>(finest) * 100u / 6u);
    if (confidence > 100) {
      confidence = 100;
    }
    return score_signature_pair(collapsed[a.level][a.hash_index],
                                collapsed[b.level][b.hash_index], confidence);
  };

  /* Process one posting list. */
  auto process_list = [&](const std::vector<Entry>& list) {
    if (list.size() < 2) {
      return;
    }
    std::size_t comparisons = 0;
    for (std::size_t i = 0; i < list.size(); ++i) {
      for (std::size_t j = i + 1; j < list.size(); ++j) {
        const std::uint32_t hi = list[i].hash_index;
        const std::uint32_t hj = list[j].hash_index;
        if (hi == hj) {
          continue;
        }
        if (dsu.find(hi) == dsu.find(hj)) {
          continue; /* already connected, the edge would change nothing */
        }
        if (++comparisons > kMaxComparisonsPerGram) {
          return;
        }
        if (score_entries(list[i], list[j]) >= threshold) {
          dsu.unite(hi, hj);
        }
      }
    }
  };

  for (const auto& group : gram_index) {
    for (const auto& posting : group.second) {
      process_list(posting.second);
    }
  }
  for (const auto& group : short_index) {
    for (const auto& posting : group.second) {
      process_list(posting.second);
    }
  }

  /* Number the clusters by first appearance. */
  std::unordered_map<std::uint32_t, std::int32_t> ids;
  std::int32_t next_id = 0;
  for (std::size_t i = 0; i < n; ++i) {
    const std::uint32_t root = dsu.find(static_cast<std::uint32_t>(i));
    auto it = ids.find(root);
    if (it == ids.end()) {
      it = ids.emplace(root, next_id++).first;
    }
    out[i] = it->second;
  }
  return 0;
}

} /* namespace rkf */
