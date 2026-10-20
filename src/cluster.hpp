/*
 * rak-fuzzy - internal clustering interface.
 */

#ifndef RKF_CLUSTER_HPP
#define RKF_CLUSTER_HPP

#include <cstddef>
#include <cstdint>

#include "ctph.hpp"

namespace rkf {

/*
 * Cluster `n` hashes with single linkage.
 *
 * Two hashes end up in the same cluster when their similarity is greater
 * than or equal to `threshold`. The returned cluster ids are numbered by
 * first appearance: the first hash always gets cluster 0, and every new
 * cluster takes the next free number.
 *
 * Returns 0 on success, a negative error code on failure.
 */
int cluster_hashes(const ParsedHash* hashes, std::size_t n, int threshold,
                   std::int32_t* out);

} /* namespace rkf */

#endif /* RKF_CLUSTER_HPP */
