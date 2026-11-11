
use strict;
use warnings;

use Test::More;
use File::Temp qw(tempfile);
use Digest::SHA qw(sha256);

use lib 'lib';

use SHA256::Reverse qw(
    smt_inner_hash
);

# ------------------------------------------------------------
# Check that Z3 is installed
# ------------------------------------------------------------

my $version_fh;

if (!open($version_fh, '-|', 'z3', '-version')) {
    plan skip_all => 'Z3 is not installed or is not on PATH';
}

my $version_output = do {
    local $/;
    <$version_fh>;
};

close $version_fh;

diag("Using $version_output");

# ------------------------------------------------------------
# Create deterministic test inputs
# ------------------------------------------------------------

my $B = pack('C*', 0..79);

my $X = pack('C4', 0x12, 0x34, 0x56, 0x78);

is(length($B), 80, 'B is exactly 80 bytes');
is(length($X), 4, 'X is exactly 4 bytes');

# ------------------------------------------------------------
# Calculate independent expected result
# ------------------------------------------------------------

my $expected_digest = sha256($B . $X);

my @expected_words = unpack('N8', $expected_digest);

# ------------------------------------------------------------
# Generate symbolic inner hash
# ------------------------------------------------------------

my $symbolic = smt_inner_hash($B);

like(
    $symbolic,
    qr/\(declare-fun x_word \(\) \(_ BitVec 32\)\)/,
    'Unknown x_word is declared'
);

like(
    $symbolic,
    qr/\(define-fun inner_out0 /,
    'Symbolic inner output is generated'
);

like(
    $symbolic,
    qr/\(define-fun inner_out7 /,
    'All eight symbolic output words are generated'
);

# ------------------------------------------------------------
# Build SMT-LIB script with a known X
# ------------------------------------------------------------

my $x_value = unpack('N', $X);

my $script = join("\n",
    '(set-logic QF_BV)',
    '(set-option :produce-models true)',
    $symbolic,
    '(assert (= x_word ' .
        sprintf('#x%08x', $x_value) .
    '))',
    '(check-sat)',
    '(get-value (inner_out0 inner_out1 inner_out2 inner_out3 ' .
        'inner_out4 inner_out5 inner_out6 inner_out7))',
    '(exit)',
);

# ------------------------------------------------------------
# Write temporary SMT-LIB file
# ------------------------------------------------------------

my ($fh, $filename) = tempfile(
    SUFFIX => '.smt2',
    UNLINK => 1
);

print {$fh} $script
    or die "Could not write SMT-LIB script: $!\n";

close $fh
    or die "Could not close SMT-LIB script: $!\n";

# ------------------------------------------------------------
# Run Z3
# ------------------------------------------------------------

open my $solver, '-|', 'z3', $filename
    or die "Could not start Z3: $!\n";

my $output = do {
    local $/;
    <$solver>;
};

close $solver;

is(
    $? >> 8,
    0,
    'Z3 completed successfully'
);

like(
    $output,
    qr/\bsat\b/,
    'Z3 reports satisfiable'
);

# ------------------------------------------------------------
# Extract symbolic output words
# ------------------------------------------------------------

my %solver_words;

while (
    $output =~ /\(inner_out([0-7])\s+#x([0-9a-fA-F]{8})\)/g
) {
    $solver_words{$1} = hex($2);
}

is(
    scalar(keys %solver_words),
    8,
    'Z3 returned all eight inner digest words'
);

# ------------------------------------------------------------
# Compare against Digest::SHA
# ------------------------------------------------------------

for my $i (0..7) {
    next unless exists $solver_words{$i};

    is(
        $solver_words{$i},
        $expected_words[$i],
        "Inner digest word $i matches Digest::SHA"
    );
}

done_testing();

