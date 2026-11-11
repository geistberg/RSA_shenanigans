
use strict;
use warnings;
use Test::More;

use lib 'lib';

use SHA256::Reverse qw(
    smt_bv32
    smt_rotr
    smt_shr
    smt_small_sigma0
    smt_small_sigma1
    smt_message_schedule
    smt_second_hash_block_words
);

# ------------------------------------------------------------
# Test SMT bit-vector helpers
# ------------------------------------------------------------

is(
    smt_bv32(0x12345678),
    '#x12345678',
    'Converts integer to SMT bit-vector literal'
);

is(
    smt_bv32(0xFFFFFFFF),
    '#xffffffff',
    'Handles maximum unsigned 32-bit value'
);

is(
    smt_rotr('x', 7),
    '((_ rotate_right 7) x)',
    'Generates rotate-right expression'
);

is(
    smt_shr('x', 3),
    '(bvlshr x (_ bv3 32))',
    'Generates logical right-shift expression'
);

like(
    smt_small_sigma0('x'),
    qr/rotate_right 7.*rotate_right 18.*bvlshr/s,
    'Generates small sigma zero expression'
);

like(
    smt_small_sigma1('x'),
    qr/rotate_right 17.*rotate_right 19.*bvlshr/s,
    'Generates small sigma one expression'
);

# ------------------------------------------------------------
# Test second-block construction
# ------------------------------------------------------------

my $b_tail = pack(
    "C*",
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B,
    0x0C, 0x0D, 0x0E, 0x0F
);

my $words = smt_second_hash_block_words($b_tail);

is(
    scalar(@$words),
    16,
    'Second block contains exactly 16 words'
);

is(
    $words->[0],
    '#x00010203',
    'First word contains first four bytes of B tail'
);

is(
    $words->[3],
    '#x0c0d0e0f',
    'Fourth word contains final four bytes of B tail'
);

is(
    $words->[4],
    'x_word',
    'Fifth word is the unknown X'
);

is(
    $words->[5],
    '#x80000000',
    'Sixth word contains SHA-256 padding'
);

for my $i (6..14) {
    is(
        $words->[$i],
        '#x00000000',
        "Word $i contains zero padding"
    );
}

is(
    $words->[15],
    '#x000002a0',
    'Final word contains the 672-bit message length'
);

# ------------------------------------------------------------
# Test complete symbolic schedule
# ------------------------------------------------------------

my $schedule = smt_message_schedule($words);

my @definitions =
    $schedule =~ /^\(define-fun w\d+ /mg;

is(
    scalar(@definitions),
    64,
    'Generates all 64 message schedule definitions'
);

like(
    $schedule,
    qr/\(define-fun w0 \(\) \(_ BitVec 32\) #x00010203\)/,
    'Schedule begins with correct known word'
);

like(
    $schedule,
    qr/\(define-fun w4 \(\) \(_ BitVec 32\) x_word\)/,
    'Schedule retains symbolic X word'
);

like(
    $schedule,
    qr/\(define-fun w16 /,
    'Generates first expanded schedule word'
);

like(
    $schedule,
    qr/\(define-fun w63 /,
    'Generates final schedule word'
);

like(
    $schedule,
    qr/rotate_right 7/,
    'Schedule includes sigma-zero rotations'
);

like(
    $schedule,
    qr/rotate_right 17/,
    'Schedule includes sigma-one rotations'
);

# ------------------------------------------------------------
# Test invalid input
# ------------------------------------------------------------

eval {
    smt_message_schedule([]);
};

like(
    $@,
    qr/Exactly 16 initial words/,
    'Rejects incorrect number of initial words'
);

eval {
    smt_second_hash_block_words('too short');
};

like(
    $@,
    qr/B tail must be exactly 16 bytes/,
    'Rejects incorrect B tail length'
);

done_testing();

