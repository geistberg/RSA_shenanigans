
use strict;
use warnings;

use Test::More;
use File::Temp qw(tempfile);

use lib 'lib';

use SHA256::Reverse qw(
    compress_block
    smt_bv32
    smt_compress_block
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
# Known SHA-256 initial state
# ------------------------------------------------------------

my @initial_state = (
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
);

# ------------------------------------------------------------
# Create a known 64-byte block
# ------------------------------------------------------------

my $block = pack('C*', 0..63);

my @block_words = unpack('N16', $block);

# ------------------------------------------------------------
# Numeric compression result
# ------------------------------------------------------------

my $numeric_result = compress_block(
    \@initial_state,
    $block
);

is(
    scalar(@$numeric_result),
    8,
    'Numeric compression returns eight words'
);

# ------------------------------------------------------------
# Generate symbolic compression equations
# ------------------------------------------------------------

my @initial_smt = map {
    smt_bv32($_)
} @initial_state;

my @block_smt = map {
    smt_bv32($_)
} @block_words;

my $symbolic = smt_compress_block(
    \@initial_smt,
    \@block_smt,
    64
);

# ------------------------------------------------------------
# Construct complete SMT-LIB script
# ------------------------------------------------------------

my $script = join("\n",
    '(set-logic QF_BV)',
    '(set-option :produce-models true)',
    $symbolic,
    '(check-sat)',
    '(get-value (out0 out1 out2 out3 out4 out5 out6 out7))',
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
    'Z3 reports the symbolic compression is satisfiable'
);

# ------------------------------------------------------------
# Extract the eight symbolic output words
# ------------------------------------------------------------

my %solver_words;

while (
    $output =~ /\(out([0-7])\s+#x([0-9a-fA-F]{8})\)/g
) {
    $solver_words{$1} = hex($2);
}

is(
    scalar(keys %solver_words),
    8,
    'Z3 returned all eight output words'
);

# ------------------------------------------------------------
# Compare symbolic and numeric results
# ------------------------------------------------------------

for my $i (0..7) {

    next unless exists $solver_words{$i};

    is(
        $solver_words{$i},
        $numeric_result->[$i],
        "Symbolic output word $i matches numeric compression"
    );
}

done_testing();

