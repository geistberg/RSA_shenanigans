# SHA-256 Reverse Engineering Research

## Project Overview

This project explores whether the internal operations of SHA-256 can be modeled symbolically and constrained mathematically to find an unknown input.

The goal is to find a four-byte value `X` such that:

```text
SHA256(SHA256(B || X))
```

produces a digest with a configurable number of trailing zero bits.

The project is intentionally **not intended to use brute force**. Instead, it builds an exact symbolic representation of SHA-256 using SMT bit-vector expressions and uses the Z3 solver to reason about the unknown input.

The implementation is written primarily in Perl, with `Digest::SHA` used as an independent reference implementation and Z3 used for symbolic constraint solving.

---

## 1. Problem Definition

The input consists of:

- `B`: A fixed, known, exactly 80-byte value.
- `X`: An unknown, exactly 4-byte value.
- `B || X`: The 84-byte input to the first SHA-256 operation.

The desired output is:

```text
SHA256(SHA256(B || X))
```

The final digest must have a configurable number of trailing zero bits.

For example, requiring 32 trailing zero bits means:

```text
SHA256(SHA256(B || X)) mod 2^32 = 0
```

The unknown value `X` contains 32 bits of information.

The ultimate objective is to construct a symbolic model of the complete operation and allow Z3 to solve for `X`, subject to the desired output constraint.

---

## 2. Important SHA-256 Structure

SHA-256 operates on 512-bit (64-byte) blocks.

### Inner hash

The first hash receives 84 bytes:

```text
B (80 bytes) || X (4 bytes)
```

This requires two SHA-256 blocks.

**Block 1:**

- Bytes 0–63 of `B`.
- Entirely known.

**Block 2:**

| Word | Contents |
|---|---|
| W0–W3 | Final 16 bytes of B |
| W4 | Unknown 32-bit value X |
| W5 | `0x80000000` |
| W6–W14 | Zero |
| W15 | `0x000002A0` |

The final word represents the original message length:

```text
84 bytes × 8 = 672 bits = 0x2A0
```

The first block is compressed numerically because all of its contents are known. Its resulting state becomes the initial state for the symbolic second-block compression.

### Outer hash

The outer hash receives the 32-byte inner digest.

It requires one SHA-256 block:

| Word | Contents |
|---|---|
| W0–W7 | Eight words of the inner digest |
| W8 | `0x80000000` |
| W9–W14 | Zero |
| W15 | `0x00000100` |

The final word represents:

```text
32 bytes × 8 = 256 bits = 0x100
```

The outer hash therefore operates entirely on symbolic values produced by the inner hash.

---

## 3. Current Project Structure

The main implementation is:

```text
lib/
  SHA256/
    Reverse.pm

t/
  symbolic_schedule.t
  symbolic_rounds.t
  symbolic_feed_forward.t
  symbolic_compression_equivalence.t
  symbolic_inner_hash.t
  symbolic_prefixes.t
  symbolic_double_hash.t
```

The module exports its public functions through `@EXPORT_OK`.

The test suite uses Perl's testing framework and invokes Z3 for symbolic verification tests.

---

## 4. Completed Development Stages

### Stage A — Symbolic Message Schedule

Implemented the SHA-256 message schedule using SMT-LIB bit-vector expressions.

Functions:

```perl
smt_bv32
smt_rotr
smt_shr
smt_small_sigma0
smt_small_sigma1
smt_message_schedule
smt_second_hash_block_words
```

The symbolic message schedule implements:

\[
W_t = \sigma_1(W_{t-2}) + W_{t-7}
      + \sigma_0(W_{t-15}) + W_{t-16}
      \pmod {2^{32}}
\]

The schedule generates all 64 words, `W0` through `W63`.

The helper `smt_second_hash_block_words` constructs the correctly padded second block for the 84-byte inner-hash input, including the symbolic `x_word`.

**Status: Complete. Tests passing.**

### Stage B — Symbolic Compression Rounds

Implemented the SHA-256 round operations using SMT-LIB expressions.

Functions:

```perl
smt_ch
smt_maj
smt_big_sigma0
smt_big_sigma1
smt_compression_rounds
```

The implementation models the SHA-256 working state:

```text
a, b, c, d, e, f, g, h
```

Each round uses the corresponding message schedule word and SHA-256 round constant.

The implementation supports a configurable round count from 1 through 64. This will be useful for reduced-round experiments.

**Status: Complete. Tests passing.**

### Stage C — Symbolic Feed-Forward and Compression

Implemented the feed-forward operation that adds the final working state back to the original compression state.

Functions:

```perl
smt_feed_forward
smt_compress_block
```

The feed-forward operation is:

\[
H'_i = H_i + S_i \pmod {2^{32}}
\]

Where:

- \(H_i\) is the original state word.
- \(S_i\) is the final working-state word.
- \(H'_i\) is the resulting hash state word.

`smt_compress_block` combines the symbolic message schedule, compression rounds, and feed-forward operation.

**Status: Complete. Tests passing.**

### Stage D — Symbolic/Numeric Compression Equivalence

Created a test that compares the symbolic compression implementation against the existing numeric Perl implementation.

The test:

1. Constructs a deterministic 64-byte block.
2. Compresses the block using the numeric implementation.
3. Generates an SMT-LIB representation of the same compression.
4. Runs Z3.
5. Compares all eight resulting 32-bit state words.

This verifies that the symbolic compression implementation agrees with the numeric implementation.

**Status: Complete. Tests passing.**

### Stage E — Symbolic Inner Hash

Implemented the symbolic inner hash.

Function:

```perl
smt_inner_hash
```

The implementation:

1. Validates that `B` is exactly 80 bytes.
2. Compresses the first 64 bytes numerically.
3. Uses the resulting state as the initial state for the second block.
4. Builds the symbolic second block.
5. Uses `x_word` as the unknown 32-bit input.
6. Generates the symbolic compression for the second block.

The resulting symbolic output words are:

```text
inner_out0
inner_out1
inner_out2
inner_out3
inner_out4
inner_out5
inner_out6
inner_out7
```

The inner hash test fixes `x_word` to a known value and compares the symbolic output against `Digest::SHA`.

**Status: Complete. Tests passing.**

### Supporting Improvement — Symbolic Name Prefixes

Added optional prefixes to the symbolic expression generators.

Updated functions:

```perl
smt_message_schedule
smt_compression_rounds
smt_feed_forward
smt_compress_block
```

This allows multiple symbolic compression operations to coexist in one SMT-LIB program without conflicting variable names.

For example:

```text
inner_w0
inner_a_0
inner_out0

outer_w0
outer_a_0
outer_out0
```

The prefix is optional, preserving backward compatibility with earlier calls.

Prefix validation also rejects invalid names.

**Status: Implemented. Tests passing.**

### Stage F — Complete Symbolic Double-SHA-256

Implemented the symbolic outer hash and combined double-hash builder.

Functions:

```perl
smt_outer_hash
smt_double_hash
```

`smt_outer_hash`:

1. Uses `inner_out0` through `inner_out7` as its input words.
2. Adds the correct SHA-256 padding.
3. Sets the original message length to 256 bits.
4. Generates the complete symbolic outer compression using the `outer` prefix.

`smt_double_hash`:

1. Validates the 80-byte `B` input.
2. Generates the symbolic inner hash.
3. Generates the symbolic outer hash.
4. Combines both into one SMT-LIB program.

The final symbolic output words are:

```text
outer_out0
outer_out1
outer_out2
outer_out3
outer_out4
outer_out5
outer_out6
outer_out7
```

The Stage F test fixes `x_word` to a known four-byte value and verifies that all eight symbolic output words match the result from:

```perl
Digest::SHA::sha256(
    Digest::SHA::sha256($B . $X)
);
```

This verifies the complete symbolic double-SHA-256 pipeline against an independent implementation.

**Status: Complete. Tests passing.**

---

## 5. Numeric SHA-256 Implementation

The project also contains a numeric SHA-256 implementation used for validation and experimentation.

Important functions include:

```perl
rotr
add32
sub32
ch
maj
big_sigma0
big_sigma1
small_sigma0
small_sigma1

forward_round
reverse_round
verify_round

message_schedule
compress_block
pad_message
sha256_raw
double_sha256
double_sha256_custom
trace_compression
reverse_compress_block
has_trailing_zero_bits
```

The numeric implementation has been tested against `Digest::SHA` using:

- Empty input.
- `"abc"`.
- `"HelloWorld"`.
- The standard quick-brown-fox test string.
- 100 repeated `A` characters.
- 1000 repeated `B` characters.

All comparisons passed.

The `reverse_round` and `reverse_compress_block` functions provide additional tools for investigating SHA-256's internal operations.

An important distinction: reversing a compression operation when its message schedule and relevant state are known is not the same as recovering an unknown message block. The latter is the actual constraint-solving problem.

---

## 6. Current Verification Status

All completed stages through Stage F have passed their tests.

The complete symbolic pipeline has been verified against the numeric SHA-256 implementation and `Digest::SHA`.

The current model correctly represents:

```text
80-byte known B
       |
       v
Known first inner block
       |
       v
Numeric intermediate state
       |
       v
Symbolic second inner block
       |
       v
32-byte symbolic inner digest
       |
       v
Symbolic outer block
       |
       v
32-byte symbolic final digest
```

The remaining work is to add the desired output constraints and experiment with Z3 solving for the unknown input.

---

## 7. Next Development Stages

### Stage G — Trailing-Zero Constraints

Implement a helper that generates SMT-LIB assertions requiring a specified number of trailing zero bits in the final digest.

Proposed function:

```perl
smt_trailing_zero_constraint($bits)
```

The helper should support values from 0 through 256.

The final digest is represented by eight big-endian 32-bit words:

```text
outer_out0 ... outer_out7
```

The least-significant word is `outer_out7`.

Examples:

**16 trailing zero bits:**

```lisp
(assert
  (= ((_ extract 15 0) outer_out7) #x0000)
)
```

**32 trailing zero bits:**

```lisp
(assert
  (= outer_out7 #x00000000)
)
```

**40 trailing zero bits:**

```lisp
(assert
  (= outer_out7 #x00000000)
)
(assert
  (= ((_ extract 7 0) outer_out6) #x00)
)
```

**64 trailing zero bits:**

```lisp
(assert (= outer_out7 #x00000000))
(assert (= outer_out6 #x00000000))
```

Tests should verify:

- Zero bits.
- Partial-word constraints.
- Exact 32-bit boundaries.
- Multiple complete words.
- The maximum of 256 bits.
- Correct behavior against known numeric digests.

### Stage H — Solve for X

Once the trailing-zero constraints are implemented, construct a complete SMT-LIB problem containing:

1. The symbolic double-hash model.
2. The unknown 32-bit declaration:

   ```lisp
   (declare-fun x_word () (_ BitVec 32))
   ```

3. The requested trailing-zero constraints.
4. A Z3 `check-sat` command.
5. A `get-value` command to retrieve `x_word`.

Start with small targets, such as 4, 8, or 12 trailing zero bits, to verify that the solver can find valid inputs.

Then progressively increase the target difficulty.

The final objective is to test whether Z3 can find an `X` satisfying a 32-bit trailing-zero requirement.

---

## 8. Important Research Considerations

### This is not ordinary brute force

The goal is to represent SHA-256's operations as exact bit-vector constraints and allow an SMT solver to reason about the unknown input.

This is a constraint-solving approach, not a guarantee that the solver will efficiently invert SHA-256.

### Solver complexity

SHA-256 is designed to resist inversion. Its operations include:

- 32-bit modular addition.
- Bitwise rotations.
- Bitwise shifts.
- XOR.
- Choice and majority functions.
- A nonlinear message schedule.
- 64 rounds per compression block.

The complete double-hash model contains 128 compression rounds.

Even though the unknown input is only 32 bits, the resulting constraint system can be extremely difficult.

The probability of a random digest having `N` trailing zero bits is:

\[
P = 2^{-N}
\]

A 32-bit trailing-zero requirement therefore has an expected random-search work factor of approximately \(2^{32}\) trials.

SMT solving may exploit the structure of the equations, but there is no guarantee it will outperform random search for the full SHA-256 problem.

### Reduced-round experiments

The symbolic compression functions support configurable round counts.

This provides an opportunity to investigate:

- Whether Z3 can solve reduced-round SHA-256.
- How solving time changes as rounds are added.
- Whether the inner or outer hash is responsible for most of the difficulty.
- How different trailing-zero requirements affect solver performance.

Reduced-round success should be treated as an experimental result, not proof that full SHA-256 can be inverted efficiently.

---

## 9. Development Environment

Current implementation:

- Language: Perl
- Numeric reference: `Digest::SHA`
- Symbolic representation: SMT-LIB bit-vectors
- Constraint solver: Z3
- Tests: Perl `Test::More` / `prove`

Run the full test suite with:

```bash
prove -v t/
```

Run an individual test with:

```bash
prove -v t/symbolic_double_hash.t
```

---

## 10. Current Milestone

**Completed:** Exact symbolic representation of the complete double-SHA-256 pipeline, verified against independent numeric implementations.

**Next:** Add final-digest trailing-zero constraints and begin solving for the unknown 32-bit input.

The project has successfully moved from implementing individual SHA-256 operations to representing the complete double-hash operation as a single symbolic constraint system.
