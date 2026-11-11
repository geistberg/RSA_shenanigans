package SHA256::Reverse;

use strict;
use warnings;
use Exporter 'import';
use Digest::SHA qw(sha256);

our @EXPORT_OK = qw(
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
    double_sha256
    verify_round
	message_schedule
	compress_block
	pad_message
	sha256_raw
	double_sha256_custom
	trace_compression
	reverse_compress_block
	has_trailing_zero_bits
	smt_bv32
	smt_rotr
	smt_shr
	smt_small_sigma0
	smt_small_sigma1
	smt_message_schedule
	smt_second_hash_block_words
	smt_ch
	smt_maj
	smt_big_sigma0
	smt_big_sigma1
	smt_compression_rounds
	smt_feed_forward
	smt_compress_block
);

use constant MASK => 0xFFFFFFFF;

# SHA-256 initial state
our @INITIAL_STATE = (
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
);

# -----------------------------------------
# Basic 32-bit operations
# -----------------------------------------

sub normalize {
    return $_[0] & MASK;
}

sub rotr {
    my ($x, $n) = @_;

    $x &= MASK;

    return (
        ($x >> $n) |
        (($x << (32 - $n)) & MASK)
    ) & MASK;
}

sub add32 {
    my $sum = 0;

    $sum += $_ for @_;

    return $sum & MASK;
}

sub sub32 {
    my ($result, @values) = @_;

    for my $value (@values) {
        $result -= $value;
    }

    return $result & MASK;
}

# -----------------------------------------
# SHA-256 logical functions
# -----------------------------------------

sub ch {
    my ($x, $y, $z) = @_;

    return (
        ($x & $y) ^
        ((~$x) & $z)
    ) & MASK;
}

sub maj {
    my ($x, $y, $z) = @_;

    return (
        ($x & $y) ^
        ($x & $z) ^
        ($y & $z)
    ) & MASK;
}

sub big_sigma0 {
    my ($x) = @_;

    return (
        rotr($x, 2) ^
        rotr($x, 13) ^
        rotr($x, 22)
    ) & MASK;
}

sub big_sigma1 {
    my ($x) = @_;

    return (
        rotr($x, 6) ^
        rotr($x, 11) ^
        rotr($x, 25)
    ) & MASK;
}

sub small_sigma0 {
    my ($x) = @_;

    return (
        rotr($x, 7) ^
        rotr($x, 18) ^
        ($x >> 3)
    ) & MASK;
}

sub small_sigma1 {
    my ($x) = @_;

    return (
        rotr($x, 17) ^
        rotr($x, 19) ^
        ($x >> 10)
    ) & MASK;
}

# -----------------------------------------
# Forward SHA-256 compression round
#
# Input:
#   state = [a,b,c,d,e,f,g,h]
#   w     = message schedule word
#   k     = round constant
#
# Output:
#   next state
# -----------------------------------------

sub forward_round {
    my ($state, $w, $k) = @_;

    die "State must contain 8 words\n"
        unless ref($state) eq 'ARRAY'
        && @$state == 8;

    my ($a,$b,$c,$d,$e,$f,$g,$h) = @$state;

    my $t1 = add32(
        $h,
        big_sigma1($e),
        ch($e,$f,$g),
        $k,
        $w
    );

    my $t2 = add32(
        big_sigma0($a),
        maj($a,$b,$c)
    );

    return [
        add32($t1,$t2),
        $a,
        $b,
        $c,
        add32($d,$t1),
        $e,
        $f,
        $g
    ];
}

# -----------------------------------------
# Reverse SHA-256 compression round
#
# Requires:
#   Complete next state
#   Known message schedule word
#   Known round constant
#
# Returns:
#   Exact previous state
# -----------------------------------------

sub reverse_round {
    my ($next, $w, $k) = @_;

    die "State must contain 8 words\n"
        unless ref($next) eq 'ARRAY'
        && @$next == 8;

    my ($na,$nb,$nc,$nd,$ne,$nf,$ng,$nh) = @$next;

    # Recover state variables directly
    my $a = $nb;
    my $b = $nc;
    my $c = $nd;

    my $e = $nf;
    my $f = $ng;
    my $g = $nh;

    # Reconstruct T2
    my $t2 = add32(
        big_sigma0($a),
        maj($a,$b,$c)
    );

    # Reconstruct T1
    my $t1 = sub32($na,$t2);

    # Recover remaining variables
    my $d = sub32($ne,$t1);

    my $h = sub32(
        $t1,
        big_sigma1($e),
        ch($e,$f,$g),
        $k,
        $w
    );

    return [
        $a,$b,$c,$d,$e,$f,$g,$h
    ];
}

# -----------------------------------------
# Independent round verification
# -----------------------------------------

sub verify_round {
    my ($original, $w, $k) = @_;

    my $forward = forward_round($original,$w,$k);

    my $recovered = reverse_round($forward,$w,$k);

    for my $i (0..7) {
        return 0 if $original->[$i] != $recovered->[$i];
    }

    return 1;
}

# -----------------------------------------
# Double SHA-256 reference function
# -----------------------------------------

sub double_sha256 {
    my ($input) = @_;

    my $first = sha256($input);

    return sha256($first);
}


# -----------------------------------------
# Official SHA-256 round constants
# -----------------------------------------

our @K = (
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
);

# -----------------------------------------
# Message schedule expansion
# -----------------------------------------

sub message_schedule {
    my ($block) = @_;

    die "Block must contain exactly 64 bytes\n"
        unless length($block) == 64;

    my @w = unpack("N16", $block);

    for my $i (16..63) {

        my $s0 = small_sigma0($w[$i-15]);
        my $s1 = small_sigma1($w[$i-2]);

        $w[$i] = add32(
            $w[$i-16],
            $s0,
            $w[$i-7],
            $s1
        );
    }

    return \@w;
}

# -----------------------------------------
# Complete SHA-256 compression block
#
# Optional third argument:
#   Array reference for intermediate states
# -----------------------------------------

sub compress_block {
    my ($state, $block, $trace) = @_;

    die "Invalid SHA-256 state\n"
        unless ref($state) eq 'ARRAY'
        && @$state == 8;

    my $w = message_schedule($block);

    my @initial = @$state;
    my @working = @$state;

    for my $i (0..63) {

        @working = @{forward_round(
            \@working,
            $w->[$i],
            $K[$i]
        )};

        if (defined $trace) {
            push @$trace, [@working];
        }
    }

    my @result;

    for my $i (0..7) {
        $result[$i] = add32(
            $initial[$i],
            $working[$i]
        );
    }

    return \@result;
}

# -----------------------------------------
# SHA-256 message padding
# -----------------------------------------

sub pad_message {
    my ($message) = @_;

    my $original_length = length($message);

    my $bit_length = $original_length * 8;

    my $padded = $message . "\x80";

    my $padding_length =
        (56 - (length($padded) % 64) + 64) % 64;

    $padded .= "\0" x $padding_length;

    $padded .= pack("Q>", $bit_length);

    return $padded;
}

# -----------------------------------------
# Complete SHA-256 implementation
# Returns raw 32-byte digest
# -----------------------------------------

sub sha256_raw {
    my ($message) = @_;

    my $padded = pad_message($message);

    my @state = @INITIAL_STATE;

    while (length($padded)) {

        my $block = substr($padded, 0, 64, "");

        my $next = compress_block(
            \@state,
            $block
        );

        @state = @$next;
    }

    return pack("N8", @state);
}

# -----------------------------------------
# Double SHA-256
# -----------------------------------------

sub double_sha256_custom {
    my ($message) = @_;

    return sha256_raw(sha256_raw($message));
}

# -----------------------------------------
# Compression trace
# -----------------------------------------

sub trace_compression {
    my ($block) = @_;

    my @trace;

    my $result = compress_block(
        \@INITIAL_STATE,
        $block,
        \@trace
    );

    return {
        rounds => \@trace,
        result => $result
    };
}


# -----------------------------------------
# Reverse a complete SHA-256 compression block
#
# Inputs:
#   final_state   = state after feed-forward
#   block         = original 64-byte message block
#   initial_state = optional starting state
#
# Returns:
#   Reconstructed working state before round 0
# -----------------------------------------

sub reverse_compress_block {
    my ($final_state, $block, $initial_state) = @_;

    die "Final state must contain 8 words\n"
        unless ref($final_state) eq 'ARRAY'
        && @$final_state == 8;

    $initial_state ||= \@INITIAL_STATE;

    die "Initial state must contain 8 words\n"
        unless ref($initial_state) eq 'ARRAY'
        && @$initial_state == 8;

    # Reconstruct all 64 message schedule words
    my $w = message_schedule($block);

    # Undo the final feed-forward addition
    my @working;

    for my $i (0..7) {
        $working[$i] = sub32(
            $final_state->[$i],
            $initial_state->[$i]
        );
    }

    # Reverse rounds 63 through 0
    for my $i (reverse 0..63) {

        @working = @{reverse_round(
            \@working,
            $w->[$i],
            $K[$i]
        )};
    }

    return \@working;
}

sub has_trailing_zero_bits {
    my ($digest, $bits) = @_;

    die "Digest must be exactly 32 bytes\n"
        unless defined($digest) && length($digest) == 32;

    die "Bit count must be between 0 and 256\n"
        unless defined($bits) && $bits >= 0 && $bits <= 256;

    return 1 if $bits == 0;

    my $whole_bytes = int($bits / 8);
    my $remaining_bits = $bits % 8;

    # Check complete trailing bytes.
    if ($whole_bytes > 0) {
        return 0
            if substr($digest, 32 - $whole_bytes, $whole_bytes)
                ne "\0" x $whole_bytes;
    }

    # Check any remaining high-order bits of the preceding byte.
    if ($remaining_bits > 0) {
        my $byte = ord(substr(
            $digest,
            31 - $whole_bytes,
            1
        ));

        my $mask = (1 << $remaining_bits) - 1;

        return 0 if ($byte & $mask) != 0;
    }

    return 1;
}


# Convert an unsigned 32-bit integer to an SMT-LIB bit-vector literal.
sub smt_bv32 {
    my ($value) = @_;

    die "Value must be defined\n" unless defined $value;

    return sprintf("#x%08x", $value & MASK);
}

# SMT-LIB expression for rotate-right.
sub smt_rotr {
    my ($value, $bits) = @_;

    die "Invalid rotation amount\n"
        unless defined($bits) && $bits >= 1 && $bits <= 31;

    return "((_ rotate_right $bits) $value)";
}

# SMT-LIB expression for logical right shift.
sub smt_shr {
    my ($value, $bits) = @_;

    die "Invalid shift amount\n"
        unless defined($bits) && $bits >= 0 && $bits <= 31;

    return "(bvlshr $value (_ bv$bits 32))";
}

# SHA-256 small sigma zero:
# ROTR(7, x) XOR ROTR(18, x) XOR SHR(3, x)
sub smt_small_sigma0 {
    my ($value) = @_;

    return "(bvxor " .
        "(bvxor " .
            smt_rotr($value, 7) . " " .
            smt_rotr($value, 18) .
        ") " .
        smt_shr($value, 3) .
    ")";
}

# SHA-256 small sigma one:
# ROTR(17, x) XOR ROTR(19, x) XOR SHR(10, x)
sub smt_small_sigma1 {
    my ($value) = @_;

    return "(bvxor " .
        "(bvxor " .
            smt_rotr($value, 17) . " " .
            smt_rotr($value, 19) .
        ") " .
        smt_shr($value, 10) .
    ")";
}

# Build all 64 symbolic SHA-256 message schedule words.
#
# Input:
#   Array reference containing 16 SMT-LIB expressions.
#
# Output:
#   String containing 64 SMT-LIB define-fun declarations.
#
# The first 16 words are supplied by the caller.
# The remaining 48 are generated using the SHA-256 recurrence.
sub smt_message_schedule {
    my ($initial_words, $prefix) = @_;

    $prefix //= '';

    die "Invalid SMT prefix\n"
        if length($prefix)
        && $prefix !~ /^[A-Za-z_][A-Za-z0-9_]*$/;

    my $name_prefix = length($prefix)
        ? $prefix . '_'
        : '';

    die "Initial words must be an array reference\n"
        unless ref($initial_words) eq 'ARRAY';

    die "Exactly 16 initial words are required\n"
        unless @$initial_words == 16;

    for my $i (0..15) {
        die "Initial word $i is undefined or empty\n"
            unless defined($initial_words->[$i])
            && length($initial_words->[$i]);
    }

    my @definitions;

    # Define the first 16 words.
    for my $i (0..15) {
        my $word_name = $name_prefix . "w$i";

        push @definitions,
            "(define-fun $word_name () (_ BitVec 32) " .
            $initial_words->[$i] .
            ")";
    }

    # Expand the schedule through word 63.
    for my $i (16..63) {
        my $previous_15 = $name_prefix . "w" . ($i - 15);
        my $previous_2  = $name_prefix . "w" . ($i - 2);
        my $previous_7  = $name_prefix . "w" . ($i - 7);
        my $previous_16 = $name_prefix . "w" . ($i - 16);

        my $sigma0 = smt_small_sigma0($previous_15);
        my $sigma1 = smt_small_sigma1($previous_2);

        my $expression =
            "(bvadd " .
                "(bvadd " .
                    "(bvadd $sigma1 $previous_7)" .
                    " $sigma0" .
                ")" .
                " $previous_16" .
            ")";

        my $word_name = $name_prefix . "w$i";

        push @definitions,
            "(define-fun $word_name () (_ BitVec 32) $expression)";
    }

    return join("\n", @definitions) . "\n";
}

# Construct the exact second block of SHA256(B || X).
#
# b_tail:
#   The final 16 bytes of the known 80-byte B.
#
# The unknown X is represented by the SMT variable x_word.
sub smt_second_hash_block_words {
    my ($b_tail) = @_;

    die "B tail must be exactly 16 bytes\n"
        unless defined($b_tail) && length($b_tail) == 16;

    my @known_words = unpack("N4", $b_tail);

    my @words = map { smt_bv32($_) } @known_words;

    # Four unknown bytes, interpreted as one big-endian word.
    push @words, "x_word";

    # SHA-256 padding begins immediately after X.
    push @words, "#x80000000";

    # Remaining zero words.
    push @words, ("#x00000000") x 9;

    # Original message length: 84 bytes * 8 = 672 bits.
    push @words, "#x000002a0";

    die "Internal error: expected exactly 16 block words\n"
        unless @words == 16;

    return \@words;
}


# SHA-256 choice function:
# Ch(x,y,z) = (x AND y) XOR (NOT x AND z)
sub smt_ch {
    my ($x, $y, $z) = @_;

    return "(bvxor " .
        "(bvand $x $y) " .
        "(bvand (bvnot $x) $z)" .
    ")";
}

# SHA-256 majority function:
# Maj(x,y,z) = (x AND y) XOR (x AND z) XOR (y AND z)
sub smt_maj {
    my ($x, $y, $z) = @_;

    return "(bvxor " .
        "(bvxor " .
            "(bvand $x $y) " .
            "(bvand $x $z)" .
        ") " .
        "(bvand $y $z)" .
    ")";
}

# SHA-256 big sigma zero:
# ROTR(2,x) XOR ROTR(13,x) XOR ROTR(22,x)
sub smt_big_sigma0 {
    my ($x) = @_;

    return "(bvxor " .
        "(bvxor " .
            smt_rotr($x, 2) . " " .
            smt_rotr($x, 13) .
        ") " .
        smt_rotr($x, 22) .
    ")";
}

# SHA-256 big sigma one:
# ROTR(6,x) XOR ROTR(11,x) XOR ROTR(25,x)
sub smt_big_sigma1 {
    my ($x) = @_;

    return "(bvxor " .
        "(bvxor " .
            smt_rotr($x, 6) . " " .
            smt_rotr($x, 11) .
        ") " .
        smt_rotr($x, 25) .
    ")";
}

# Generate symbolic SHA-256 compression rounds.
#
# Arguments:
#   $initial_state: array reference of 8 SMT-LIB expressions
#   $round_count:   number of rounds to generate (1..64)
#
# The message schedule words must already be defined as w0..w63.
#
# Returns:
#   SMT-LIB define-fun declarations for every round state.
sub smt_compression_rounds {
    my ($initial_state, $round_count, $prefix) = @_;

    $prefix //= '';

    die "Invalid SMT prefix\n"
        if length($prefix)
        && $prefix !~ /^[A-Za-z_][A-Za-z0-9_]*$/;

    my $name_prefix = length($prefix)
        ? $prefix . '_'
        : '';

    die "Initial state must be an array reference\n"
        unless ref($initial_state) eq 'ARRAY';

    die "Initial state must contain exactly 8 words\n"
        unless @$initial_state == 8;

    die "Round count must be between 1 and 64\n"
        unless defined($round_count)
        && $round_count =~ /^\d+$/
        && $round_count >= 1
        && $round_count <= 64;

    for my $i (0..7) {
        die "Initial state word $i is undefined or empty\n"
            unless defined($initial_state->[$i])
            && length($initial_state->[$i]);
    }

    my @names = map {
        $name_prefix . $_
    } qw(a b c d e f g h);

    my @definitions;

    # Define the initial working state.
    for my $i (0..7) {
        push @definitions,
            "(define-fun $names[$i]_0 () (_ BitVec 32) " .
            $initial_state->[$i] .
            ")";
    }

    # Generate the requested number of rounds.
    for my $t (0..$round_count - 1) {
        my $a = $names[0] . "_$t";
        my $b = $names[1] . "_$t";
        my $c = $names[2] . "_$t";
        my $d = $names[3] . "_$t";
        my $e = $names[4] . "_$t";
        my $f = $names[5] . "_$t";
        my $g = $names[6] . "_$t";
        my $h = $names[7] . "_$t";

        my $sigma1 = smt_big_sigma1($e);
        my $choice = smt_ch($e, $f, $g);

        my $schedule_word = $name_prefix . "w$t";

        my $t1 = "(bvadd " .
            "(bvadd " .
                "(bvadd " .
                    "(bvadd $h $sigma1) " .
                    "$choice" .
                ") " .
                smt_bv32($K[$t]) .
            ") " .
            $schedule_word .
        ")";

        my $t2 = "(bvadd " .
            smt_big_sigma0($a) . " " .
            smt_maj($a, $b, $c) .
        ")";

        my @next_state = (
            "(bvadd $t1 $t2)",
            $a,
            $b,
            $c,
            "(bvadd $d $t1)",
            $e,
            $f,
            $g
        );

        for my $i (0..7) {
            my $next_round = $t + 1;

            push @definitions,
                "(define-fun $names[$i]_$next_round () " .
                "(_ BitVec 32) " .
                $next_state[$i] .
                ")";
        }
    }

    return join("\n", @definitions) . "\n";
}


# Generate the SHA-256 feed-forward operation.
#
# Arguments:
#   $initial_state: array reference containing 8 SMT-LIB expressions
#   $round_count:   number of rounds previously generated
#
# The round generator names the final working state:
#   a_N, b_N, c_N, d_N, e_N, f_N, g_N, h_N
#
# This function generates:
#   out0 = initial_state[0] + a_N
#   ...
#   out7 = initial_state[7] + h_N
#
# All additions are 32-bit modular additions.
sub smt_feed_forward {
    my ($initial_state, $round_count, $prefix) = @_;

    $prefix //= '';

    die "Invalid SMT prefix\n"
        if length($prefix)
        && $prefix !~ /^[A-Za-z_][A-Za-z0-9_]*$/;

    my $name_prefix = length($prefix)
        ? $prefix . '_'
        : '';

    die "Initial state must be an array reference\n"
        unless ref($initial_state) eq 'ARRAY';

    die "Initial state must contain exactly 8 words\n"
        unless @$initial_state == 8;

    die "Round count must be between 1 and 64\n"
        unless defined($round_count)
        && $round_count =~ /^\d+$/
        && $round_count >= 1
        && $round_count <= 64;

    for my $i (0..7) {
        die "Initial state word $i is undefined or empty\n"
            unless defined($initial_state->[$i])
            && length($initial_state->[$i]);
    }

    my @names = map {
        $name_prefix . $_
    } qw(a b c d e f g h);

    my @definitions;

    for my $i (0..7) {
        my $final_working_word =
            $names[$i] . "_" . $round_count;

        my $output_name = $name_prefix . "out$i";

        push @definitions,
            "(define-fun $output_name () (_ BitVec 32) " .
            "(bvadd " .
                $initial_state->[$i] . " " .
                $final_working_word .
            "))";
    }

    return join("\n", @definitions) . "\n";
}

# Generate a complete symbolic SHA-256 compression block.
#
# Arguments:
#   $initial_state: 8 SMT-LIB expressions
#   $block_words:   16 SMT-LIB expressions
#   $round_count:   number of rounds (1..64)
#
# The generated output state is named out0 through out7.
#
# This function assumes that the generated block is the only
# compression block in the current SMT-LIB namespace.
sub smt_compress_block {
    my ($initial_state, $block_words, $round_count, $prefix) = @_;

    $prefix //= '';

    die "Invalid SMT prefix\n"
        if length($prefix)
        && $prefix !~ /^[A-Za-z_][A-Za-z0-9_]*$/;

    die "Initial state must be an array reference\n"
        unless ref($initial_state) eq 'ARRAY';

    die "Block words must be an array reference\n"
        unless ref($block_words) eq 'ARRAY';

    die "Initial state must contain exactly 8 words\n"
        unless @$initial_state == 8;

    die "Block must contain exactly 16 words\n"
        unless @$block_words == 16;

    die "Round count must be between 1 and 64\n"
        unless defined($round_count)
        && $round_count =~ /^\d+$/
        && $round_count >= 1
        && $round_count <= 64;

    my $schedule = smt_message_schedule(
        $block_words,
        $prefix
    );

    my $rounds = smt_compression_rounds(
        $initial_state,
        $round_count,
        $prefix
    );

    my $feed_forward = smt_feed_forward(
        $initial_state,
        $round_count,
        $prefix
    );

    return join(
        "\n",
        $schedule,
        $rounds,
        $feed_forward
    );
}

1;
