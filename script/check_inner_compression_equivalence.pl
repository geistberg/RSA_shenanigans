
use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../lib";

use SHA256::Reverse qw(
    compress_block
    smt_bv32
    smt_second_hash_block_words
    smt_compress_block
    smt_inner_message_schedule
    smt_compression_rounds
    smt_feed_forward
);

my $b = pack("C*", 0..79);

my $first_block = substr($b, 0, 64);
my $b_tail = substr($b, 64, 16);

my $state_after_block_1 = compress_block(
	\@SHA256::Reverse::INITIAL_STATE,
    $first_block
);

my @initial_state = map {
    smt_bv32($_)
} @$state_after_block_1;

# General-purpose implementation.
my $general_words = smt_second_hash_block_words(
    $b_tail
);

my $general_compression = smt_compress_block(
    \@initial_state,
    $general_words,
    64,
    'general'
);

# Specialized implementation.
my $special_schedule = smt_inner_message_schedule(
    $b_tail,
    'specialized'
);

my $special_rounds = smt_compression_rounds(
    \@initial_state,
    64,
    'specialized'
);

my $special_feed_forward = smt_feed_forward(
    \@initial_state,
    64,
    'specialized'
);

my $special_compression = join(
    "\n",
    $special_schedule,
    $special_rounds,
    $special_feed_forward
);

# Require all eight output words to be identical.
my @differences = map {
    "(not (= general_out$_ specialized_out$_))"
} 0..7;

my $comparison = "(assert (or\n" .
    join("\n", @differences) .
    "\n))\n";

my $smt = join(
    "\n",
    '(set-logic QF_BV)',
	'(declare-fun x_word () (_ BitVec 32))',
    $general_compression,
    $special_compression,
	$comparison,
    '(check-sat)',
    '(get-value (x_word ' .
        join(' ', map { "general_out$_" } 0..7) . ' ' .
        join(' ', map { "specialized_out$_" } 0..7) .
    '))',
    ''
);

my $smt_file = 'inner_compression_equivalence.smt2';

open my $fh, '>', $smt_file
    or die "Cannot write $smt_file: $!\n";

print {$fh} $smt;

close $fh
    or die "Cannot close $smt_file: $!\n";

open my $z3, '-|', 'z3', '-smt2', $smt_file
    or die "Cannot execute Z3: $!\n";

my $result = do {
    local $/;
    <$z3>;
};

close $z3;

if ($result =~ /^\s*unsat\b/m) {
    print "Z3 result: unsat\n\n";
    print "PASS: All eight compression output words are equivalent\n";
    print "for every possible x_word.\n";
}
elsif ($result =~ /^\s*sat\b/m) {
    print "FAIL: The two compression implementations differ.\n";
    print "Z3 counterexample:\n$result\n";
    exit 1;
}
else {
    die "Z3 could not prove equivalence:\n$result\n";
}

