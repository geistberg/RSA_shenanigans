
use strict;
use warnings;

use Test::More;

use lib 'lib';

use SHA256::Reverse qw(
    smt_bv32
    smt_message_schedule
    smt_compression_rounds
    smt_feed_forward
    smt_compress_block
);

my @initial_state = map { smt_bv32($_) } (0..7);
my @block_words   = map { smt_bv32($_) } (0..15);

# ------------------------------------------------------------
# Test 1: Default names remain unchanged
# ------------------------------------------------------------

my $default_schedule = smt_message_schedule(\@block_words);

like($default_schedule, qr/\(define-fun w0 /,
    'Default schedule uses w0');

like($default_schedule, qr/\(define-fun w63 /,
    'Default schedule uses w63');

my $default_rounds = smt_compression_rounds(
    \@initial_state, 2
);

like($default_rounds, qr/\(define-fun a_0 /,
    'Default rounds use a_0');

like($default_rounds, qr/\(define-fun h_2 /,
    'Default rounds use h_2');

my $default_feed = smt_feed_forward(
    \@initial_state, 2
);

like($default_feed, qr/\(define-fun out0 /,
    'Default feed-forward uses out0');

# ------------------------------------------------------------
# Test 2: Prefix message schedule
# ------------------------------------------------------------

my $inner_schedule = smt_message_schedule(
    \@block_words,
    'inner'
);

like($inner_schedule, qr/\(define-fun inner_w0 /,
    'Prefixed schedule uses inner_w0');

like($inner_schedule, qr/\(define-fun inner_w63 /,
    'Prefixed schedule uses inner_w63');

like($inner_schedule, qr/inner_w1/,
    'Schedule references prefixed words');

unlike($inner_schedule, qr/\(define-fun w0 /,
    'Prefixed schedule does not define unprefixed w0');

# ------------------------------------------------------------
# Test 3: Prefix compression rounds
# ------------------------------------------------------------

my $inner_rounds = smt_compression_rounds(
    \@initial_state,
    2,
    'inner'
);

like($inner_rounds, qr/\(define-fun inner_a_0 /,
    'Prefixed rounds use inner_a_0');

like($inner_rounds, qr/\(define-fun inner_h_2 /,
    'Prefixed rounds use inner_h_2');

like($inner_rounds, qr/inner_w0/,
    'Rounds reference prefixed schedule words');

# ------------------------------------------------------------
# Test 4: Prefix feed-forward
# ------------------------------------------------------------

my $inner_feed = smt_feed_forward(
    \@initial_state,
    2,
    'inner'
);

like($inner_feed, qr/\(define-fun inner_out0 /,
    'Prefixed feed-forward uses inner_out0');

like($inner_feed, qr/\(define-fun inner_out7 /,
    'Prefixed feed-forward uses inner_out7');

like($inner_feed, qr/inner_a_2/,
    'Feed-forward references prefixed final state');

# ------------------------------------------------------------
# Test 5: Complete prefixed compression
# ------------------------------------------------------------

my $inner = smt_compress_block(
    \@initial_state,
    \@block_words,
    2,
    'inner'
);

my $outer = smt_compress_block(
    \@initial_state,
    \@block_words,
    2,
    'outer'
);

like($inner, qr/\(define-fun inner_w0 /,
    'Complete inner compression has prefixed schedule');

like($inner, qr/\(define-fun inner_out7 /,
    'Complete inner compression has prefixed output');

like($outer, qr/\(define-fun outer_w0 /,
    'Complete outer compression has prefixed schedule');

like($outer, qr/\(define-fun outer_out7 /,
    'Complete outer compression has prefixed output');

my $combined = $inner . "\n" . $outer;

like($combined, qr/inner_out0/,
    'Combined script contains inner outputs');

like($combined, qr/outer_out0/,
    'Combined script contains outer outputs');

unlike($combined, qr/\(define-fun out0 /,
    'Combined script has no unprefixed output definitions');

# ------------------------------------------------------------
# Test 6: Invalid prefixes are rejected
# ------------------------------------------------------------

my $error;

eval {
    smt_message_schedule(\@block_words, 'bad-prefix!');
};

$error = $@;

like($error, qr/Invalid SMT prefix/,
    'Invalid prefix is rejected');

done_testing();

