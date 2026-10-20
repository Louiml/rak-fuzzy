/*
 * rak_fuzzy - fuzzy hashing (CTPH + TLSH-like) native library for the Rak
 * language.
 *
 * The exported surface is plain C. No exceptions, no C++ types, no
 * structures cross the boundary. Every function validates its pointers,
 * lengths and capacities before touching memory, and never writes past the
 * caller supplied `out_cap`.
 *
 * Error convention
 * ----------------
 *   0            -> success (or, for rf_compare / rf_tlsh_distance, a
 *                   legitimate score of zero)
 *   RF_ERR_*     -> negative error code
 *   rf_compare   -> 0..100 similarity, negative on error
 *   rf_tlsh_distance -> 0..100 distance (0 = identical), negative on error
 *
 * Thread safety: the library keeps no global mutable state. All functions are
 * re-entrant and may be called concurrently from different threads.
 */

#ifndef RAK_FUZZY_H
#define RAK_FUZZY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Export decoration                                                    */
/* ------------------------------------------------------------------ */

#if defined(_WIN32)
#  if defined(RAK_FUZZY_BUILDING)
#    define RF_API __declspec(dllexport)
#  else
#    define RF_API __declspec(dllimport)
#  endif
#else
#  if defined(__GNUC__) && __GNUC__ >= 4
#    define RF_API __attribute__((visibility("default")))
#  else
#    define RF_API
#  endif
#endif

/* ------------------------------------------------------------------ */
/* Error codes                                                          */
/* ------------------------------------------------------------------ */

#define RF_OK              0   /* success                                */
#define RF_ERR_NULL       (-1) /* a required pointer argument was NULL   */
#define RF_ERR_CAPACITY   (-2) /* the output buffer is too small         */
#define RF_ERR_IO         (-3) /* the file could not be read              */
#define RF_ERR_FORMAT     (-4) /* malformed hash string                   */
#define RF_ERR_RANGE      (-5) /* an argument was out of range            */
#define RF_ERR_UNSUPPORTED (-6)/* feature not built into this library     */
#define RF_ERR_INTERNAL   (-7) /* unexpected internal failure             */

/* ------------------------------------------------------------------ */
/* Sizing constants                                                     */
/* ------------------------------------------------------------------ */

/* Longest signature (in base64 characters) produced for one block size. */
#define RF_MAX_SIG_CHARS 64

/*
 * Capacity required by rf_hash_buffer / rf_hash_file for their `out`
 * buffer, including the NUL terminator.
 *
 * Worst case is "<block size>:<64 chars>:<64 chars>\0" where the block size
 * is rendered in decimal and is bounded by 10 digits.
 */
#define RF_HASH_OUT_CAPACITY 141

/* Capacity required by rf_tlsh_buffer for its `out` buffer. */
#define RF_TLSH_OUT_CAPACITY 32

/* ------------------------------------------------------------------ */
/* CTPH (context triggered piecewise hashing)                          */
/* ------------------------------------------------------------------ */

/*
 * Hash an in-memory buffer.
 *
 * Produces a string of the form "<block size>:<sig1>:<sig2>\0" where sig1 is
 * the signature computed with the reported block size and sig2 the one
 * computed with twice that block size.
 *
 * `data` may be NULL only when `len` is 0.
 * Writes at most `out_cap` bytes (including the NUL). If the formatted hash
 * does not fit, nothing is written and RF_ERR_CAPACITY is returned.
 */
RF_API int rf_hash_buffer(const uint8_t* data, uint64_t len,
                           char* out, uint64_t out_cap);

/*
 * Hash a file. The file is streamed in fixed size chunks, so the memory
 * footprint is constant and independent of the file size.
 *
 * `path` is a NUL terminated OS path. On failure nothing is written to `out`
 * and RF_ERR_IO is returned.
 */
RF_API int rf_hash_file(const char* path,
                         char* out, uint64_t out_cap);

/*
 * Compare two CTPH hashes.
 *
 * Returns a similarity score in 0..100, or a negative error code. Two hashes
 * that are not comparable (block sizes neither equal nor a factor of two
 * apart) score 0. Malformed input yields RF_ERR_FORMAT.
 */
RF_API int rf_compare(const char* hash_a, const char* hash_b);

/* ------------------------------------------------------------------ */
/* Clustering                                                           */
/* ------------------------------------------------------------------ */

/*
 * Cluster `n` hashes that are joined by '\n' into a single NUL terminated
 * string.
 *
 * `hashes_joined` must contain exactly `n` lines (a trailing newline after
 * the last hash is allowed and does not create an extra line). Every line
 * must be a well formed CTPH hash, otherwise RF_ERR_FORMAT is returned.
 *
 * `cluster_ids_out` receives exactly `n` int32 cluster ids. Clusters are
 * numbered by first appearance, so the ids are stable for a given input
 * order: 0, 1, 2, ... in the order the clusters are first encountered.
 *
 * `threshold` is a similarity score in 0..100; two hashes are joined when
 * their similarity is greater than or equal to the threshold.
 */
RF_API int rf_cluster(const char* hashes_joined, uint64_t n, int threshold,
                      int32_t* cluster_ids_out);

/* ------------------------------------------------------------------ */
/* TLSH-like locality sensitive digest (optional build component)       */
/* ------------------------------------------------------------------ */

/*
 * Compute a TLSH-style digest of a buffer.
 *
 * The digest is a NUL terminated ASCII string of the form
 * "T1<checksum:4><length:8><q1:4><q2:4><q3:4>", 26 characters in total.
 *
 * When the library was built without the TLSH component this returns
 * RF_ERR_UNSUPPORTED.
 */
RF_API int rf_tlsh_buffer(const uint8_t* data, uint64_t len,
                           char* out, uint64_t out_cap);

/*
 * Distance between two TLSH digests. Lower means more similar; 0 means the
 * digests are identical. The result is in 0..100. Malformed input yields
 * RF_ERR_FORMAT.
 */
RF_API int rf_tlsh_distance(const char* digest_a, const char* digest_b);

/* ------------------------------------------------------------------ */
/* Misc                                                                 */
/* ------------------------------------------------------------------ */

/*
 * Version string of the library, e.g. "rak-fuzzy 1.0.0". The returned
 * pointer is owned by the library and stays valid for the lifetime of the
 * process. Never NULL.
 */
RF_API const char* rf_version(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* RAK_FUZZY_H */
