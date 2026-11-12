
#!/usr/bin/env perl

use strict;
use warnings;

use lib 'lib';

use SHA256::Reverse qw(
    smt_message_schedule
    smt_inner_message_schedule
);

# Use a deterministic 16-byte tail.
my $b_tail = pack("C*", 64..79);

# Construct the 16 initial words for the general schedule.
my @initial_words;

my @known_words = unpack("N4", $b_tail);

for my $value (@known_words) {
    push @initial_words, sprintf("(_ bv%u 32)", $value);
}

# W4 is the unknown 32-bit value.
push @initial_words, "x_word";

# Padding and message length.
push @initial_words, "(_ bv2147483648 32)";
push @initial_words, ("(_ bv0 32)") x 9;
push @initial_words, "(_ bv672 32)";

die "Expected 16 initial words\n"
    unless @initial_words == 16;

# Generate both schedules with different prefixes.
my $general = smt_message_schedule(
    \@initial_words,
    "general"
);

my $specialized = smt_inner_message_schedule(
    $b_tail,
    "specialized"
);

# Assert that at least one corresponding word differs.
my @differences;

for my $i (0..63) {
    push @differences,
        "(not (= general_w$i specialized_w$i))";
}

my $smt = <<'SMT';
(set-logic QF_BV)
(declare-fun x_word () (_ BitVec 32))
SMT

$smt .= $general;
$smt .= $specialized;

$smt .= "(assert (or\n";
$smt .= join("\n", @differences);
$smt .= "\n))\n";
$smt .= "(check-sat)\n";

# Write the SMT file.
my $smt_file = "schedule_equivalence.smt2";

open my $fh, ">", $smt_file
    or die "Cannot write $smt_file: $!";

print {$fh} $smt;

close $fh
    or die "Cannot close $smt_file: $!";

# Run Z3.
open my $z3, "-|", "z3", "-smt2", $smt_file
    or die "Cannot execute Z3: $!";

my $result = do {
    local $/;
    <$z3>;
};

close $z3;

print "Z3 result: $result";

if ($result =~ /^\s*unsat\b/m) {
    print "\nPASS: All 64 schedule words are equivalent "
        . "for every possible x_word.\n";
}
elsif ($result =~ /^\s*sat\b/m) {
    print "\nFAIL: Z3 found an x_word that produces "
        . "different schedule words.\n";
}
else {
    print "\nINCONCLUSIVE: Z3 did not complete the proof.\n";
}

