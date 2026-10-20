# rak-fuzzy

Fuzzy hashing for the [Rak](https://github.com/) language: a native C++
shared library that turns files and byte buffers into *similarity preserving*
hashes, compares two such hashes with a 0..100 score, and groups a set of
hashes into clusters of near duplicates.

The primary algorithm is **CTPH** (context triggered piecewise hashing, the
technique behind `ssdeep`). A second, independent algorithm — a simplified
**TLSH-style** locality sensitive digest — is available behind a build flag
and is never mixed with the CTPH results.

Typical uses:

* grouping malware variants that share most of their code,
* finding near-duplicate documents or images,
* tracking modified copies of a leaked file,
* triage in forensic investigations ("which of these 5000 samples are
  actually the same file?").

---

## 1. What fuzzy hashing is

A cryptographic hash answers one question: *are these two byte strings
identical?* It is designed so that a single changed bit changes the whole
digest. That is exactly wrong for triage work, where the interesting
question is *are these two files nearly the same?*

A fuzzy hash keeps the *shape* of the data instead of its exact value. The
file is cut into chunks whose boundaries are decided by the content, and
every chunk contributes one character to a short signature. Two files that
share most of their chunks produce similar signatures, and the similarity
of two signatures is measured with an edit distance.

The result is a short string (`"6144:+6fsqTgeJtbGm6p4HxJJZVi6V/CDA1t:..."`)
that:

* is stable — the same file always produces the same hash, on every
  platform,
* is comparable — two hashes can be scored against each other,
* is short — 64 characters per granularity, so a multi-gigabyte file
  produces a hash that fits in a log line,
* is *not* a security primitive. It is not collision resistant against an
  adversary, and it does not replace a cryptographic hash.

---

## 2. Repository layout

```
rak-fuzzy/
  include/rak_fuzzy.h      the exported C ABI (the only public surface)
  src/ctph.hpp  src/ctph.cpp   CTPH hashing and comparison
  src/tlsh_like.hpp  src/tlsh_like.cpp   TLSH-style digest (optional)
  src/cluster.hpp  src/cluster.cpp       single linkage clustering
  src/api.cpp              the exported C functions
  tests/test_ctph.cpp      hashing, comparison, edge cases, benchmark
  tests/test_cluster.cpp   clustering, error handling, fuzzing
  examples/hash_file.rak   Rak: hash a file, compare two files
  examples/cluster_dir.rak Rak: cluster a directory, print a cited report
  Makefile  CMakeLists.txt  build systems
```

No third party dependencies. C++17, the standard library only.

---

## 3. Building

### 3.1 MSYS2 / MinGW-w64 (Windows)

```sh
pacman -S --needed mingw-w64-x86_64-gcc make
```

Then, from an MSYS2 *MinGW64* shell in the repository root:

```sh
make            # build/rak_fuzzy.dll plus the test binaries
make test       # build and run the test suite
make bench      # run the tests including the throughput benchmark
make sanitizer  # build and run the tests with -fsanitize=address,undefined
make TLSH=0     # build without the TLSH-like digest
```

The Windows link adds `-static` on top of `-static-libgcc
-static-libstdc++` so that the DLL does not depend on
`libwinpthread-1.dll`; `rak_fuzzy.dll` can be dropped next to any host
application without shipping extra runtime libraries.

> When switching between platforms in the same checkout, remove the build
> directory first (`make clean`): the object files of a Windows build and of
> a Linux build are not interchangeable.

### 3.2 Linux

```sh
make
make test
make TLSH=0     # build without the TLSH-like digest
```

The same Makefile produces `build/librak_fuzzy.so`. The Linux build adds
`-fPIC` to the compile step.

### 3.3 CMake

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build
```

Options:

| Option | Default | Meaning |
| --- | --- | --- |
| `RAK_FUZZY_ENABLE_TLSH` | `ON` | build the TLSH-like digest |
| `RAK_FUZZY_SANITIZE` | `OFF` | build with address and UB sanitizers |

The CMake path was verified on Windows with Ninja; the Makefile path was
verified on Windows (MinGW-w64) and on Linux (Debian 13 / g++ 16.2).

### 3.4 Flags

```
-O2 -std=c++17 -Wall -Wextra -shared -static-libgcc -static-libstdc++
```

plus `-fPIC` on Linux and `-static` on Windows (see 3.1).

---

## 4. API reference

The exported surface is plain C. No exceptions, no C++ types, no structures
cross the boundary; every function validates its pointers, lengths and
capacities, and never writes past `out_cap`.

```c
#include "rak_fuzzy.h"
```

### Error codes

| Code | Name | Meaning |
| --- | --- | --- |
| `0` | `RF_OK` | success |
| `-1` | `RF_ERR_NULL` | a required pointer argument was `NULL` |
| `-2` | `RF_ERR_CAPACITY` | the output buffer is too small |
| `-3` | `RF_ERR_IO` | the file could not be read |
| `-4` | `RF_ERR_FORMAT` | malformed hash string |
| `-5` | `RF_ERR_RANGE` | an argument was out of range |
| `-6` | `RF_ERR_UNSUPPORTED` | the feature is not in this build |
| `-7` | `RF_ERR_INTERNAL` | unexpected internal failure |

### `rf_hash_buffer`

```c
int rf_hash_buffer(const uint8_t* data, uint64_t len,
                    char* out, uint64_t out_cap);
```

Hashes `len` bytes at `data` and writes `"<block size>:<sig1>:<sig2>\0"`
into `out`. `data` may be `NULL` only when `len` is `0`. If the formatted
hash does not fit into `out_cap`, nothing is written and
`RF_ERR_CAPACITY` is returned. `out_cap` should be at least
`RF_HASH_OUT_CAPACITY` (141).

### `rf_hash_file`

```c
int rf_hash_file(const char* path, char* out, uint64_t out_cap);
```

Same output as `rf_hash_buffer`, but the file is streamed from disk in
64 KiB chunks. The memory footprint is constant and independent of the file
size, so multi-gigabyte files are fine. Returns `RF_ERR_IO` if the file
cannot be opened or read.

### `rf_compare`

```c
int rf_compare(const char* hash_a, const char* hash_b);
```

Returns a similarity score in `0..100`, or a negative error code.
Malformed input yields `RF_ERR_FORMAT`.

The rules:

1. The block sizes must be equal, or one must be exactly twice the other.
   Otherwise the score is `0`.
2. The matching signature pair is selected accordingly (see §5.3).
3. The two signatures must share a common substring of at least **7**
   characters, otherwise the score is `0`. This is what keeps unrelated
   files from receiving a small but non-zero score by accident.
4. Runs of more than three identical characters are collapsed to three
   before the comparison, so that a signature full of padding does not
   dominate the distance.
5. The score is `100 * (1 - E / L)`, where `E` is the weighted edit
   distance (insertion/deletion cost 1, substitution cost 2) and `L` is the
   length of the longer signature.
6. The score is scaled down for small block sizes: a hash with block size 3
   can only come from a very short file, where a high score means much
   less than it does for a multi-megabyte sample. The factor is
   `min(1, block size / 6)`. An *exact* signature match always scores
   `100`, no matter how small the block size.

### `rf_cluster`

```c
int rf_cluster(const char* hashes_joined, uint64_t n, int threshold,
               int32_t* cluster_ids_out);
```

`hashes_joined` contains `n` hashes separated by `'\n'` (a trailing newline
after the last hash is allowed). Every line must be a well formed hash,
otherwise `RF_ERR_FORMAT` is returned.

Two hashes end up in the same cluster when their similarity is greater than
or equal to `threshold` (single linkage, union-find over the threshold
graph). The returned cluster ids are numbered **by first appearance**: the
first hash always gets cluster `0`, and every new cluster takes the next
free number, so the numbering is stable for a given input order.

`threshold` must be in `0..100`; `0` means "everything is one cluster".

### `rf_tlsh_buffer` and `rf_tlsh_distance`

```c
int rf_tlsh_buffer(const uint8_t* data, uint64_t len,
                    char* out, uint64_t out_cap);
int rf_tlsh_distance(const char* digest_a, const char* digest_b);
```

The TLSH-style digest is a **separate algorithm**; it is never mixed with
the CTPH scores. `rf_tlsh_buffer` writes a 26 character digest
`"T1<checksum:4><length:8><q1:4><q2:4><q3:4>"`.
`rf_tlsh_distance` returns a distance in `0..100` where **lower means more
similar** (`0` means the digests are identical). Malformed input yields
`RF_ERR_FORMAT`. When the library is built with
`-DRAK_FUZZY_ENABLE_TLSH=OFF`, both functions return
`RF_ERR_UNSUPPORTED`.

### `rf_version`

```c
const char* rf_version(void);
```

Returns a static string, e.g. `"rak-fuzzy 1.0.0 (ctph + tlsh-like)"`. The
pointer is owned by the library and stays valid for the lifetime of the
process.

### Thread safety

The library keeps no mutable global state. All functions are re-entrant and
may be called concurrently from different threads.

---

## 5. How the algorithm works

### 5.1 Chunking

A rolling hash runs over a 7 byte window. At every input byte the hash is
evaluated and a chunk boundary is placed when

```
rolling_hash % block_size == block_size - 1
```

Because the window is short, the hash is a *pure function of the current
window* (the history is cancelled exactly), so a single modified byte only
perturbs the chunking for the following 7 bytes. After that the rolling
hash is identical to the unmodified file again and the original chunk
boundaries reappear. This is the property that makes the signature survive
edits, insertions and deletions instead of degrading into noise.

Two signatures are produced in a single pass: one at `block_size` and one
at `2 * block_size`. Both are needed because a file can be compared with
another file whose block size is twice as large.

A single remainder per byte is enough for both tests: with
`r = rolling_hash % (2 * block_size)`, the level-0 boundary condition is
`r == block_size - 1` or `r == 2 * block_size - 1`, and the level-1
condition is `r == 2 * block_size - 1`.

### 5.2 The signature characters

Every chunk contributes one base64 character, derived from a running
FNV-1a hash of the bytes of that chunk (6 bits per character). The running
hash is reset at every boundary. The trailing partial chunk is hashed as
well — without it, appending a few bytes to a file would leave the
signature completely unchanged, which would hide the most common kind of
tampering.

The block size is chosen from the input length: the smallest value of the
sequence `3, 6, 12, 24, 48, ...` that yields roughly 48 chunks. The
signature budget is 64 characters per granularity; if a signature still
outgrows it (the chunk count is random), the pass is repeated with a
doubled block size.

### 5.3 Comparing two hashes

```
bs == bs      -> compare sig1 with sig1 and sig2 with sig2, take the best
bs_b == 2*bs_a -> compare sig2 of a (chunk size 2*bs_a) with sig1 of b
bs_a == 2*bs_b -> compare sig1 of a with sig2 of b
otherwise      -> 0
```

### 5.4 Clustering

Comparing every pair of `N` hashes is `O(N^2)`, which is too slow for a
directory of a few thousand samples. The implementation builds an inverted
index of the 7 character substrings of every signature (a gram is encoded
in 42 bits, because the alphabet has 64 symbols and 7 * 6 = 42).

Two hashes can only reach a non-zero similarity when their matched
signatures share a common substring of at least seven characters, so they
must share a gram. Hashes that share no gram are never scored.

The index is grouped by the *absolute* block size of a signature (the
chunk size it was computed with: `block size` for the first signature of a
hash, `2 * block size` for the second). Two signatures can only be
compared when their absolute block sizes are equal, which is exactly the
pairing rule of §5.3 — so the candidate pairs are automatically compatible
and no invalid pair is ever scored.

Clustering is then single linkage with union-find. Pairs that are already
in the same cluster are skipped, and the number of similarity computations
per gram is capped (50000) so that a corpus of thousands of near identical
files cannot blow up the runtime; reaching the cap costs precision, never
correctness of the program.

---

## 6. Using it from Rak

### 6.1 The examples

```sh
# hash a file and compare it with a second one
rakc run examples/hash_file.rak src/ctph.cpp src/ctph.hpp

# cluster every file of a directory
rakc run examples/cluster_dir.rak ./samples 40
```

Both examples run on the interpreter (`rakc run`) and on the bytecode VM
(`rakc vm`). The library is located automatically next to the script or in
`./build`, and can be overridden with a third/fourth command line argument.

`cluster_dir.rak` wraps every group in `cite(...)` and finishes with
`report(...)`, so the output carries the tool, the target and the
timestamp of the finding:

```
cluster 0: 3 file(s): samples/a.bin, samples/b.bin, samples/c_modified.bin
{target: samples, tool: rak-fuzzy, ts: 1792532134}

1. cluster 0: 3 file(s): samples/a.bin, ...
cluster 1: 1 file(s): samples/d_other.bin

--- Sources ---
[1] tool=rak-fuzzy target=samples ts=1792532134
```

### 6.2 The pattern

```rak
let lib = ffi_load("./rak_fuzzy.dll")

// Rak allocates the output buffer, so the library can never write past its
// end and Rak knows the length of the region it reads back.
let out = ffi_alloc(256)

let rc = c_int(lib.call("rf_hash_file", ["samples/a.bin", out, 256]))
if rc == 0 {
    let hash = ffi_cstr_to_string(out)
    dump hash
}
ffi_free(out)
```

### 6.3 FFI limitations hit along the way, and the workarounds

These are properties of the Rak FFI layer (`docs/content/ffi.md` in the Rak
repository), not of this library.

1. **`lib.call()` returns the raw 64 bit register, and a 32 bit `int`
   return is zero extended.** A C function returning `int` puts its result
   in `eax`; the trampoline reads `rax`, so `-1` arrives in Rak as
   `4294967295`. The examples therefore normalise the value:

   ```rak
   fn c_int(v: i64) -> i64 {
       if v >= 2147483648 { return v - 4294967296 }
       return v
   }
   ```

   The declarative `extern "C" { fn f() -> i32 }` form has the same quirk
   (`bits as u32 as i64`); declaring `-> i64` avoids it, because `i64` is
   sign extended.

2. **A returned `const char*` is useless without its length.** Rak refuses
   to read a region it does not know the length of, so `rf_version()` can
   only be read back after `ffi_trust(ptr, len)`. This is the reason the
   library writes its results into a caller supplied buffer instead of
   returning a pointer: the caller (Rak) knows the length of the buffer it
   allocated with `ffi_alloc`, so `ffi_cstr_to_string` works with no
   `ffi_trust` at all.

3. **A string passed to C is owned by the call frame and is freed when the
   call returns.** The library copies whatever it needs and never keeps a
   pointer into the argument.

4. **Arguments are limited to 8 integer/pointer registers.** The library
   uses at most four.

5. **No float arguments, no float returns through `lib.call()`.** The
   library uses integers only; the score is an `int` in `0..100`.

6. **`argv()` only exists on the interpreter.** The examples use `args()`
   (the whole process command line: `[program, script, arg1, ...]`), which
   works on both backends.

7. **A top level `return` does not stop a Rak script.** The examples are
   written with `if/else` instead of early returns.

8. **`ffi_alloc` buffers are formally `align 1`.** The library only ever
   writes `char` data into them, so alignment never matters.

---

## 7. Tests

```sh
make test          # or: ctest --test-dir build
make bench         # additionally prints the throughput
make sanitizer     # -fsanitize=address,undefined (Linux, or any GCC with
                   # the sanitizer runtimes installed)
```

What the suite covers:

| Area | Check |
| --- | --- |
| Format | the hash is `bs:sig1:sig2`, each signature at most 64 characters |
| Determinism | the same input always produces the same hash, through the buffer *and* the file interface |
| Identical input | a hash compared with itself scores exactly `100` |
| Unrelated input | two random buffers score `0` |
| Mutations | one flipped byte, two appended bytes and four deleted bytes in a 1 MiB buffer all score high but below 100 |
| Damage growth | replacing 4 KiB / 64 KiB / 256 KiB / 768 KiB of a 1 MiB buffer gives a monotonically decreasing score |
| Insertion | a 4 KiB block inserted in the middle of a 1 MiB file still scores above 90 |
| Block size neighbours | a hash and a hand built hash with twice the block size compare correctly; a hash with an unrelated block size scores 0 |
| Edge cases | empty input, input smaller than the rolling window, an all-zero buffer, a buffer that is not NUL terminated, a too small output buffer, `NULL` pointers |
| Large file | a generated 100 MiB file is hashed by streaming; the peak working set does not grow (see below) |
| Clustering | identical, modified and unrelated samples; cluster numbering by first appearance; threshold semantics; error codes |
| Fuzzing | ~8000 random and malformed hash strings (missing colons, absurd block sizes, non-base64 characters, random bytes) through `rf_compare` and `rf_cluster`; no crash, only scores in `0..100` or negative error codes |
| Sanitizers | the whole suite under `-fsanitize=address,undefined` |

Peak memory for the 100 MiB file: the process working set did not grow at
all while hashing (12 MiB before and after on Windows, 5.4 MiB on Linux),
because the file is read in 64 KiB chunks. The library's own footprint is a
64 KiB stream buffer plus a few hundred bytes of state.

---

## 8. Measured performance

Measured on an Intel Core i5-10400F @ 2.90 GHz, single threaded, g++ 16.2
with `-O2`:

| | Windows (native NTFS) | Linux (WSL2, g++ 16.2) |
| --- | --- | --- |
| CTPH, in-memory buffer | **376 MB/s** (358 MiB/s) | 290 MB/s (276 MiB/s) |
| CTPH, streamed from a file | 290 MB/s (277 MiB/s) | 55 MB/s (52 MiB/s) |

The target of 200 MB/s is met on both platforms. The Linux file number is
low because the test file lives on a Windows drive mounted through WSL
(`/mnt/d`), which is dominated by the filesystem, not by the hashing.

The hot loop keeps its whole state in local variables: because a `char`
array may alias anything, a naive implementation has to reload the rolling
hash, the window and the counters after every single byte, which costs
more than twice the hashing itself.

---

## 9. Limitations

Honest list of things this library does **not** do:

* **The scores are not compatible with `ssdeep`.** The output format looks
  similar (`bs:sig1:sig2` versus ssdeep's `bs:sig1:sig2`), but the
  algorithm is an independent implementation: different rolling hash,
  different chunk hash, different comparison. A hash produced here cannot
  be compared with an `ssdeep` hash, and the scores are not on the same
  scale. This is deliberate: the `ssdeep` implementation is GPL, and this
  library is an original implementation of the published technique.
* **Very small files score badly.** A file of a few hundred bytes produces
  a signature of only a handful of characters. The rule that two
  signatures must share at least 7 characters means that such files are
  reported as unrelated (`0`) unless they are byte-identical in their
  signature. The same applies to the trailing-partial-chunk character,
  which is very sensitive to the exact file length.
* **Scores are not calibrated.** `100` means "the signatures are
  identical", `0` means "not comparable or nothing in common". Everything
  in between is a relative measure. Pick a threshold for your corpus
  (40..70 works well for "near duplicate" in practice) and validate it on
  your own data.
* **Uniform files are a special case.** A file of all zero bytes has an
  identical rolling window at every position, so the modular boundary
  condition can never fire. Such files fall back to fixed size chunking,
  which produces a valid, length sensitive signature — but the fallback
  signature is not comparable with a normal signature of the same block
  size.
* **The clusterer is approximate in the extreme case.** The number of
  similarity computations per 7-gram is capped at 50000. With more than
  that many nearly identical files sharing a gram, some pairs are not
  scored and the clustering can split a group that a full quadratic
  comparison would have merged. The cap is high enough that it does not
  trigger for realistic corpora.
* **A single byte change in the middle of a large file shifts the
  chunking locally, not globally.** This is a feature (that is why the
  score stays high), but it also means that a change which alters the
  *content* of many chunks at once drives the score down quickly: in the
  test suite, replacing 6 % of a 1 MiB file costs about 40 % of the score
  and replacing 25 % costs about half of it.
* **The TLSH-like digest is a simplified, non-standard variant.** It does
  not produce TLSH compatible digests, its checksum is a folded FNV-1a
  instead of TLSH's `vhash`, and its quartiles are a very coarse summary:
  two different files of the same size can have identical quartiles, in
  which case only the content checksum keeps the distance above zero.
* **Fuzzy hashes are not a security primitive.** They are trivially
  forgeable and are meant for triage, not for integrity.

---

## 10. Licence

Original implementation. The CTPH technique is described in the
literature; no `ssdeep` source code was copied.
