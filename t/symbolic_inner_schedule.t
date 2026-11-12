
use strict;
use warnings;

use Test::More;
use lib 'lib';

use SHA256::Reverse qw(
    smt_inner_message_schedule
);

my $b_tail = pack("C*", 64..79);

my $schedule = smt_inner_message_schedule($b_tail);

# Verify that all 64 schedule words are defined.
for my $i (0..63) {
    like(
        $schedule,
        qr/\(define-fun w$i \(\) \(_ BitVec 32\)/,
        "Schedule word W$i is defined"
    );
}

# Verify the symbolic input word.
like(
    $schedule,
    qr/\(define-fun w4 \(\) \(_ BitVec 32\) x_word\)/,
    'W4 references x_word'
);

# Verify the known padding words.
like(
    $schedule,
    qr/\(define-fun w5 \(\) \(_ BitVec 32\) #x80000000\)/,
    'W5 contains SHA-256 padding'
);

like(
    $schedule,
    qr/\(define-fun w15 \(\) \(_ BitVec 32\) #x000002a0\)/,
    'W15 contains the 672-bit message length'
);

# Verify that at least one later schedule word is symbolic.
like(
    $schedule,
    qr/\(define-fun w16 \(\) \(_ BitVec 32\)/,
    'W16 is generated'
);

done_testing();

