use strict;
use warnings;

use Test::More;
use FindBin;
use lib "$FindBin::Bin/../lib";

use SHA256::Reverse qw(
    smt_trailing_zero_constraint
);

# Zero bits: no constraint is necessary.
is(
    smt_trailing_zero_constraint(0),
    '',
    'Zero trailing bits produces no constraint'
);

# Partial-word constraints.
is(
    smt_trailing_zero_constraint(8),
    "(assert (= ((_ extract 7 0) outer_out7) (_ bv0 8)))\n",
    '8 trailing bits'
);

is(
    smt_trailing_zero_constraint(16),
    "(assert (= ((_ extract 15 0) outer_out7) (_ bv0 16)))\n",
    '16 trailing bits'
);

is(
    smt_trailing_zero_constraint(31),
    "(assert (= ((_ extract 30 0) outer_out7) (_ bv0 31)))\n",
    '31 trailing bits'
);

# Exact word boundaries.
is(
    smt_trailing_zero_constraint(32),
    "(assert (= outer_out7 #x00000000))\n",
    '32 trailing bits'
);

is(
    smt_trailing_zero_constraint(64),
    join(
        '',
        "(assert (= outer_out7 #x00000000))\n",
        "(assert (= outer_out6 #x00000000))\n",
    ),
    '64 trailing bits'
);

# Cross-word boundaries.
is(
    smt_trailing_zero_constraint(40),
    join(
        '',
        "(assert (= outer_out7 #x00000000))\n",
        "(assert (= ((_ extract 7 0) outer_out6) (_ bv0 8)))\n",
    ),
    '40 trailing bits'
);

is(
    smt_trailing_zero_constraint(33),
    join(
        '',
        "(assert (= outer_out7 #x00000000))\n",
        "(assert (= ((_ extract 0 0) outer_out6) (_ bv0 1)))\n",
    ),
    '33 trailing bits'
);

# Maximum digest length.
my $all_zero_words = join(
    '',
    map {
        "(assert (= outer_out$_ #x00000000))\n"
    } reverse 0..7
);

is(
    smt_trailing_zero_constraint(256),
    $all_zero_words,
    '256 trailing bits'
);

# Prefix support.
is(
    smt_trailing_zero_constraint(32, 'test'),
    "(assert (= test_out7 #x00000000))\n",
    'Custom prefix'
);

is(
    smt_trailing_zero_constraint(32, ''),
    "(assert (= out7 #x00000000))\n",
    'Empty prefix'
);

# Invalid inputs.
for my $invalid (undef, -1, 257, 1.5, 'abc') {
    my $ok = eval {
        smt_trailing_zero_constraint($invalid);
        1;
    };

    ok(!$ok, 'Reject invalid trailing-zero bit count');
}

{
    my $ok = eval {
        smt_trailing_zero_constraint(32, 'bad-prefix!');
        1;
    };

    ok(!$ok, 'Reject invalid prefix');
}

done_testing();

