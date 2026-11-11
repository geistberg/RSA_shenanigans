
use strict;
use warnings;
use Test::More;

use lib 'lib';

use SHA256::Reverse qw(
    smt_feed_forward
    smt_compress_block
);

# ------------------------------------------------------------
# Initial state
# ------------------------------------------------------------

my @initial_state = map {
    sprintf("#x%08x", $_)
} (
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
);

# ------------------------------------------------------------
# Test feed-forward generation
# ------------------------------------------------------------

my $feed_forward = smt_feed_forward(
    \@initial_state,
    64
);

my @definitions =
    $feed_forward =~ /^\(define-fun /mg;

is(
    scalar(@definitions),
    8,
    'Feed-forward generates eight output state definitions'
);

like(
    $feed_forward,
    qr/\(define-fun out0 .*bvadd.*a_64/s,
    'First output adds initial state to final a state'
);

like(
    $feed_forward,
    qr/\(define-fun out1 .*bvadd.*b_64/s,
    'Second output adds initial state to final b state'
);

like(
    $feed_forward,
    qr/\(define-fun out7 .*bvadd.*h_64/s,
    'Last output adds initial state to final h state'
);

like(
    $feed_forward,
    qr/\(bvadd #x6a09e667 a_64\)/,
    'Feed-forward uses the first initial state word'
);

# ------------------------------------------------------------
# Test a reduced-round feed-forward operation
# ------------------------------------------------------------

my $reduced_feed_forward = smt_feed_forward(
    \@initial_state,
    4
);

like(
    $reduced_feed_forward,
    qr/\(bvadd #x6a09e667 a_4\)/,
    'Reduced-round feed-forward uses correct final state name'
);

# ------------------------------------------------------------
# Test complete symbolic compression block
# ------------------------------------------------------------

my @block_words = map {
    sprintf("#x%08x", $_)
} (0..15);

my $compression = smt_compress_block(
    \@initial_state,
    \@block_words,
    4
);

like(
    $compression,
    qr/\(define-fun w0 /,
    'Complete compression includes message schedule'
);

like(
    $compression,
    qr/\(define-fun w16 /,
    'Complete compression includes expanded schedule'
);

like(
    $compression,
    qr/\(define-fun a_4 /,
    'Complete compression includes final round state'
);

like(
    $compression,
    qr/\(define-fun out0 /,
    'Complete compression includes feed-forward output'
);

like(
    $compression,
    qr/\(define-fun out7 /,
    'Complete compression includes all eight output words'
);

# ------------------------------------------------------------
# Test invalid inputs
# ------------------------------------------------------------

eval {
    smt_feed_forward([], 64);
};

like(
    $@,
    qr/Initial state must contain exactly 8 words/,
    'Rejects incorrect feed-forward state size'
);

eval {
    smt_feed_forward(\@initial_state, 0);
};

like(
    $@,
    qr/Round count must be between 1 and 64/,
    'Rejects invalid feed-forward round count'
);

eval {
    smt_compress_block(\@initial_state, [], 4);
};

like(
    $@,
    qr/Block must contain exactly 16 words/,
    'Rejects incorrect compression block size'
);

done_testing();

