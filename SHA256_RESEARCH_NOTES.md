# SHA-256 Reverse Engineering Research Notes

## 1. Project Objective

The objective of this project is to investigate whether we can use the internal mathematical structure of SHA-256, combined with an SMT solver, to find a four-byte unknown value `X` satisfying a configurable trailing-zero condition.

The target expression is:

```text
SHA256(SHA256(B || X))
```

Where:

- `B` is a fixed, known 80-byte input.
- `X` is an unknown, exactly 4-byte value (32 unknown bits).
- The resulting double SHA-256 digest must have a specified number of trailing zero bits.

For example, a 32-bit target means:

```text
SHA256(SHA256(B || X)) mod 2^32 = 0
```

The primary goal is to explore SHA-256's internal operations mathematically rather than simply brute-forcing all possible values of `X`.

The implementation language is Perl, with `Digest::SHA` used as an independent reference implementation. Z3 is used for symbolic bit-vector reasoning.

---

## 2. Mathematical Background

SHA-256 operates on 512-bit (64-byte) blocks.

Its internal state consists of eight 32-bit words:

```text
H0, H1, H2, H3, H4, H5, H6, H7
```

Each compression operation:

1. Expands 16 input words into a 64-word message schedule.
2. Performs 64 rounds of SHA-256 transformations.
3. Adds the resulting working state back into the original state (feed-forward).

All arithmetic is modulo 2^32.

The important SHA-256 functions are:

```text
Ch(x,y,z)  = (x AND y) XOR (NOT x AND z)

Maj(x,y,z) = (x AND y) XOR (x AND z) XOR (y AND z)

Σ0(x) = ROTR(x,2) XOR ROTR(x,13) XOR ROTR(x,22)

Σ1(x) = ROTR(x,6) XOR ROTR(x,11) XOR ROTR(x,25)

σ0(x) = ROTR(x,7) XOR ROTR(x,18) XOR SHR(x,3)

σ1(x) = ROTR(x,17) XOR ROTR(x,19) XOR SHR(x,10)
```

The message schedule recurrence is:

```text
W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]
```

for `t = 16..63`.

---

## 3. Input Structure and SHA-256 Padding

### Original input

```text
B = 80 bytes
X = 4 bytes
```

The first SHA-256 receives:

```text
B || X
```

Total length:

```text
84 bytes = 672 bits
```

### Inner hash: block 1

The first 64 bytes of `B` form the first complete block.

All bytes are known, so this block can be compressed numerically using our Perl implementation.

### Inner hash: block 2

The second block contains:

```text
B[64..79]   16 known bytes
X            4 unknown bytes
0x80         1 padding byte
0x00        35 zero bytes
length       8 bytes
```

The final 64-bit length field represents 672 bits.

In big-endian 32-bit words:

| Word | Contents |
|---|---|
| W0-W3 | Final 16 bytes of B |
| W4 | Unknown 32-bit X |
| W5 | `0x80000000` |
| W6-W14 | Zero |
| W15 | `0x000002A0` |

This block is the first major symbolic target.

### Outer hash

The inner SHA-256 digest is 32 bytes.

The outer SHA-256 receives those 32 bytes and applies standard SHA-256 padding:

```text
32 digest bytes
0x80
23 zero bytes
64-bit length = 256 bits
```

This produces one 64-byte block.

The eventual objective is to connect the symbolic inner digest to this outer compression operation.

---

## 4. Project Structure

Current known project files:

```text
project/
│
├── lib/
│   └── SHA256/
│       └── Reverse.pm
│
├── t/
│   ├── reverse_compression.t
│   ├── symbolic_schedule.t
│   ├── symbolic_rounds.t
│   ├── symbolic_feed_forward.t
│   ├── symbolic_compression_equivalence.t
│   ├── trailing_zero_bits.t
│   └── ...
│
└── SHA256_RESEARCH_NOTES.md
```

The exact names of earlier test files may vary according to the working directory.

The main implementation is:

```text
lib/SHA256/Reverse.pm
```

The module exports selected functions through `@EXPORT_OK`.

---

# 5. Completed Development Stages

## Stage 1 — Basic SHA-256 Operations

Implemented the fundamental SHA-256 operations in Perl:

- `rotr`
- `add32`
- `sub32`
- `ch`
- `maj`
- `big_sigma0`
- `big_sigma1`
- `small_sigma0`
- `small_sigma1`
- `forward_round`
- `reverse_round`
- `verify_round`

Also implemented:

- `message_schedule`
- `compress_block`
- `pad_message`
- `sha256_raw`
- `double_sha256`
- `double_sha256_custom`
- `trace_compression`
- `reverse_compress_block`

The custom SHA-256 implementation was compared against `Digest::SHA` using several test messages, including:

```text
""
"abc"
"HelloWorld"
"The quick brown fox jumps over the lazy dog"
100 repeated A characters
1000 repeated B characters
```

All comparisons passed.

### Important correction

The original `sub32` implementation accepted only two arguments, although it was being used with multiple subtrahends.

It was corrected to:

```perl
sub sub32 {
    my ($result, @values) = @_;

    for my $value (@values) {
        $result -= $value;
    }

    return $result & MASK;
}
```

All tests passed after this correction.

---

## Stage 2 — Trailing Zero Bit Detection

Implemented:

```perl
has_trailing_zero_bits($digest, $bits)
```

This function determines whether a 32-byte SHA-256 digest has the requested number of trailing zero bits.

It supports:

```text
0 through 256 trailing bits
```

Tests cover:

- Zero bits
- Whole-byte boundaries
- Partial-byte boundaries
- The complete 256-bit digest
- Invalid inputs

Test file:

```text
t/trailing_zero_bits.t
```

All tests pass.

---

## Stage 3 — Symbolic Message Schedule

Introduced SMT-LIB bit-vector expression generation.

The symbolic functions include:

```perl
smt_bv32
smt_rotr
smt_shr
smt_small_sigma0
smt_small_sigma1
smt_message_schedule
smt_second_hash_block_words
```

The symbolic message schedule generates the 64 SHA-256 schedule words using 32-bit bit-vector operations.

The schedule recurrence is encoded directly into SMT-LIB.

The function:

```perl
smt_second_hash_block_words($b_tail)
```

accepts the final 16 known bytes of `B` and creates the 16 symbolic block words, including the unknown `X` word and padding.

The unknown word is represented as an SMT bit-vector expression.

Test file:

```text
t/symbolic_schedule.t
```

All tests pass.

---

## Stage 4 — Symbolic SHA-256 Rounds

Implemented symbolic versions of the SHA-256 round functions:

```perl
smt_ch
smt_maj
smt_big_sigma0
smt_big_sigma1
smt_compression_rounds
```

The symbolic round generator accepts:

- An initial state consisting of eight SMT-LIB expressions.
- A round count between 1 and 64.

It generates the round state definitions:

```text
a_0 through h_0
a_1 through h_1
...
a_N through h_N
```

The implementation references the generated message schedule words and the standard SHA-256 constants.

Test file:

```text
t/symbolic_rounds.t
```

All tests pass.

---

## Stage 5 — Symbolic Feed-Forward and Compression

Implemented:

```perl
smt_feed_forward
smt_compress_block
```

The feed-forward operation combines the final working state with the original initial state.

For example:

```text
out0 = initial_state[0] + a_final
out1 = initial_state[1] + b_final
...
out7 = initial_state[7] + h_final
```

All additions are 32-bit bit-vector additions, so they automatically wrap modulo 2^32.

The complete symbolic compression function combines:

1. Message schedule generation.
2. Symbolic round generation.
3. Feed-forward.

Its current interface is:

```perl
smt_compress_block(
    $initial_state,
    $block_words,
    $round_count
);
```

### Current naming limitation

The symbolic functions currently use fixed SMT-LIB names:

```text
w0 ... w63
a_0 ... h_N
out0 ... out7
```

This is sufficient for testing one compression block in an SMT-LIB namespace.

However, multiple symbolic compression blocks cannot yet coexist safely in the same script because their generated names would collide.

**Next improvement:** add optional prefixes to the symbolic generators.

For example:

```text
inner_w0
inner_a_0
inner_out0

outer_w0
outer_a_0
outer_out0
```

This will allow the inner and outer SHA-256 computations to coexist in one solver model.

Test file:

```text
t/symbolic_feed_forward.t
```

All tests pass.

---

## Stage 6 — Symbolic Compression Equivalence Verification

This stage verifies that the symbolic compression generator produces exactly the same results as the numeric Perl SHA-256 implementation.

The test uses:

- A known SHA-256 initial state.
- A deterministic 64-byte input block containing bytes 0 through 63.
- All 16 message words supplied as known constants.
- All 64 SHA-256 rounds.

The numeric implementation calculates the expected result using:

```perl
compress_block($state, $block);
```

The symbolic implementation generates SMT-LIB using:

```perl
smt_compress_block(
    \@initial_smt,
    \@block_smt,
    64
);
```

Z3 evaluates the symbolic equations and returns:

```text
out0 out1 out2 out3 out4 out5 out6 out7
```

The test compares all eight symbolic output words against the numeric result.

Test file:

```text
t/symbolic_compression_equivalence.t
```

### Result

**All eight output words match.**

The complete symbolic compression implementation has therefore passed an integration test against the numeric implementation.

The complete test suite also passes.

This is an important milestone: the symbolic SHA-256 compression equations are now validated against our working numeric implementation for the test vector.

---

# 6. Current Development Status

| Component | Status |
|---|---|
| Numeric SHA-256 implementation | Complete and tested |
| Numeric double SHA-256 | Complete and tested |
| Reverse round operations | Implemented and tested |
| Reverse compression with known schedule | Implemented and tested |
| Trailing-zero detection | Complete and tested |
| Symbolic bit-vector primitives | Complete and tested |
| Symbolic message schedule | Complete and tested |
| Symbolic SHA-256 rounds | Complete and tested |
| Symbolic feed-forward | Complete and tested |
| Symbolic compression | Complete and tested |
| Symbolic/numeric equivalence test | Passing |
| Multiple-block SMT naming | Not yet implemented |
| Two-block symbolic inner hash | Not yet implemented |
| Symbolic outer hash | Not yet implemented |
| Trailing-zero constraint in Z3 | Not yet implemented |
| Solver-based search for X | Not yet implemented |

---

# 7. Planned Development Stages

## Stage E — Build the Two-Block Inner Hash

The first block of `B` is entirely known.

We will calculate its resulting SHA-256 state numerically:

```perl
my $state_after_block_1 = compress_block(
    \@INITIAL_STATE,
    $first_64_bytes
);
```

The second block contains the unknown four-byte `X`.

We will use the resulting first-block state as the initial state for symbolic compression of the second block.

Conceptually:

```text
INITIAL_STATE
      |
      v
Numeric compression of B[0..63]
      |
      v
Known intermediate state
      |
      v
Symbolic compression of B[64..79] || X || padding
      |
      v
Symbolic 256-bit inner digest
```

This will establish the first complete symbolic hash:

```text
SHA256(B || X)
```

## Stage F — Build the Symbolic Outer Hash

The outer SHA-256 takes the symbolic 256-bit inner digest as its input.

We will construct the outer block using the eight symbolic output words from the inner hash.

The symbolic digest words will be arranged in big-endian order, followed by the outer SHA-256 padding.

The outer compression will use the standard SHA-256 initial state.

The result will be:

```text
SHA256(SHA256(B || X))
```

represented entirely as symbolic 32-bit bit-vectors.

This is where the optional naming prefixes become essential.

## Stage G — Add the Trailing-Zero Constraint

Once the complete symbolic double hash is working, we will constrain the final output.

For a target of 32 trailing zero bits:

```text
out7 = 0
```

Because SHA-256's digest is represented as eight big-endian 32-bit words, the final word contains the least-significant 32 bits.

For a configurable target of `N` trailing bits, we will construct the appropriate bit-vector constraint.

Examples:

| Target | Constraint |
|---|---|
| 8 bits | Lowest 8 bits equal zero |
| 16 bits | Lowest 16 bits equal zero |
| 24 bits | Lowest 24 bits equal zero |
| 32 bits | Final 32-bit word equals zero |
| 40 bits | Final word plus lowest 8 bits of preceding word equal zero |

The solver will be responsible for finding an `X` satisfying the constraint.

## Stage H — Solve for X

The final unknown will be declared as:

```lisp
(declare-fun x_word () (_ BitVec 32))
```

The unknown word will feed into the second block of the inner SHA-256.

Z3 will attempt to find a value satisfying the requested trailing-zero condition.

If successful, the model's `x_word` value will be extracted and converted into four bytes.

The candidate will then be independently verified using:

```perl
Digest::SHA
```

The final verification must confirm:

1. `X` is exactly four bytes.
2. The first SHA-256 digest is correct.
3. The second SHA-256 digest is correct.
4. The requested number of trailing zero bits is present.

---

# 8. Important Research Considerations

## Brute-force complexity

A four-byte unknown represents:

```text
2^32 = 4,294,967,296 possible values
```

For a random 256-bit digest, the probability of finding a digest with `N` trailing zero bits is approximately:

```text
1 / 2^N
```

Therefore, a 32-bit trailing-zero target has an expected random-search cost of approximately:

```text
2^32 attempts
```

The purpose of this project is to investigate whether the structure of SHA-256 can be exploited through symbolic reasoning to do better than straightforward enumeration.

However, a solver may still struggle with the full 64-round SHA-256 construction. Successful symbolic modeling does not guarantee that Z3 can solve the complete problem efficiently.

Reduced-round experiments may be useful for understanding solver behavior and identifying bottlenecks.

## Reverse compression versus inversion

The existing reverse compression functionality can reverse a compression operation when the necessary message schedule and intermediate information are known.

That does not mean SHA-256 can be straightforwardly inverted when the message contains unknown bits.

The symbolic solver approach is intended to handle those unknown bits by representing the SHA-256 operations as bit-vector constraints.

---

# 9. Development Philosophy

The project should continue in small, verifiable stages.

For each stage:

1. Implement a small set of functions.
2. Add a dedicated Perl test.
3. Run the dedicated test.
4. Run the complete test suite.
5. Verify the result before proceeding.

Where possible, compare symbolic results against the existing numeric implementation.

Do not introduce the complete double-hash solver until each individual compression component has been validated.

The ultimate goal is not merely to produce an answer, but to understand whether and how the internal mathematical structure of SHA-256 can be exploited.

---

# 10. Immediate Next Steps

The next development session should begin with:

**Stage E preparation: introduce optional naming prefixes into the symbolic functions.**

The functions requiring prefix support are:

```perl
smt_message_schedule
smt_compression_rounds
smt_feed_forward
smt_compress_block
```

The prefix should be optional so that existing tests and callers continue to work with the current default names.

After prefix support is implemented and tested, we will:

1. Calculate the first 64-byte block of `B` numerically.
2. Use the resulting state as the initial state for the symbolic second block.
3. Introduce `x_word` as the unknown 32-bit value.
4. Verify the symbolic inner hash against the numeric implementation using a known test value for `X`.

At that point, we will have a complete symbolic model of the first SHA-256 operation.

**Current milestone: Stages 1–6 are complete, and the full test suite passes.**
