
use strict;
use warnings;
use Test::More;

use lib 'lib';

use SHA256::Reverse qw(
    smt_ch
    smt_maj
    smt_big_sigma0
    smt_big_sigma1
    smt_compression_rounds
);

# ------------------------------------------------------------
# Test the symbolic SHA-256 functions
# ------------------------------------------------------------

like(
    smt_ch('x', 'y', 'z'),
    qr/bvand.*bvnot/s,
    'Choice function uses AND and NOT'
);

is(
    smt_maj('x', 'y', 'z'),
    '(bvxor (bvxor (bvand x y) (bvand x z)) (bvand y z))',
    'Majority function generates the correct expression'
);

like(
    smt_big_sigma0('x'),
    qr/rotate_right 2.*rotate_right 13.*rotate_right 22/s,
    'Big sigma zero uses correct rotations'
);

like(
    smt_big_sigma1('x'),
    qr/rotate_right 6.*rotate_right 11.*rotate_right 25/s,
    'Big sigma one uses correct rotations'
);

# ------------------------------------------------------------
# Test round generation
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

my $one_round = smt_compression_rounds(
    \@initial_state,
    1
);

my @one_round_definitions =
    $one_round =~ /^\(define-fun /mg;

is(
    scalar(@one_round_definitions),
    16,
    'One round produces 8 initial and 8 updated state definitions'
);

like(
    $one_round,
    qr/\(define-fun a_0 /,
    'Defines initial a state'
);

like(
    $one_round,
    qr/\(define-fun h_0 /,
    'Defines initial h state'
);

like(
    $one_round,
    qr/\(define-fun a_1 /,
    'Defines updated a state'
);

like(
    $one_round,
    qr/\(define-fun h_1 /,
    'Defines updated h state'
);

like(
    $one_round,
    qr/\(bvadd.*w0/s,
    'Round zero incorporates message word w0'
);

# ------------------------------------------------------------
# Test multiple rounds
# ------------------------------------------------------------

my $four_rounds = smt_compression_rounds(
    \@initial_state,
    4
);

my @four_round_definitions =
    $four_rounds =~ /^\(define-fun /mg;

is(
    scalar(@four_round_definitions),
    40,
    'Four rounds produce 40 state definitions'
);

like(
    $four_rounds,
    qr/\(define-fun a_4 /,
    'Four-round model contains final a state'
);

like(
    $four_rounds,
    qr/\(define-fun e_4 /,
    'Four-round model contains final e state'
);

# ------------------------------------------------------------
# Test full 64-round generation
# ------------------------------------------------------------

my $full_rounds = smt_compression_rounds(
    \@initial_state,
    64
);

my @full_definitions =
    $full_rounds =~ /^\(define-fun /mg;

is(
    scalar(@full_definitions),
    520,
    '64 rounds produce 520 state definitions'
);

like(
    $full_rounds,
    qr/\(define-fun a_64 /,
    'Full model contains final a state'
);

like(
    $full_rounds,
    qr/\(define-fun h_64 /,
    'Full model contains final h state'
);

# ------------------------------------------------------------
# Test invalid arguments
# ------------------------------------------------------------

eval {
    smt_compression_rounds([], 1);
};

like(
    $@,
    qr/Initial state must contain exactly 8 words/,
    'Rejects incorrect initial state size'
);

eval {
    smt_compression_rounds(\@initial_state, 0);
};

like(
    $@,
    qr/Round count must be between 1 and 64/,
    'Rejects zero rounds'
);

eval {
    smt_compression_rounds(\@initial_state, 65);
};

like(
    $@,
    qr/Round count must be between 1 and 64/,
    'Rejects more than 64 rounds'
);

done_testing();

