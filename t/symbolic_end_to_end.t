
use strict;
use warnings;

use Test::More;
use FindBin;
use lib "$FindBin::Bin/../lib";

use Digest::SHA qw(sha256);
use File::Temp qw(tempfile);

use SHA256::Reverse qw(
    smt_double_hash
    smt_trailing_zero_constraint
);

# ------------------------------------------------------------
# Test input
# ------------------------------------------------------------

my $B = pack('C*', 0..79);

my $X = pack('H*', '12345678');

# Calculate the expected digest independently.
my $inner_digest = sha256($B . $X);
my $expected_digest = sha256($inner_digest);

# ------------------------------------------------------------
# Count the actual trailing zero bits.
# ------------------------------------------------------------

sub count_trailing_zero_bits {
    my ($digest) = @_;

    my $count = 0;

    for my $byte (reverse unpack('C*', $digest)) {
        if ($byte == 0) {
            $count += 8;
            next;
        }

        while (($byte & 1) == 0) {
            $count++;
            $byte >>= 1;
        }

        last;
    }

    return $count;
}

my $actual_zero_bits = count_trailing_zero_bits($expected_digest);

diag("Expected digest: " . unpack('H*', $expected_digest));
diag("Actual trailing zero bits: $actual_zero_bits");

# ------------------------------------------------------------
# Run a generated SMT-LIB program through Z3.
# ------------------------------------------------------------

sub run_z3 {
    my ($target_bits) = @_;

    my ($fh, $filename) = tempfile(
        SUFFIX => '.smt2',
        UNLINK => 1
    );

    my $smt = smt_double_hash($B);

    print {$fh} "(set-logic QF_BV)\n";
    print {$fh} "(set-option :produce-models true)\n";
    print {$fh} "(set-option :timeout 120000)\n";

    print {$fh} $smt;

    my $x_value = sprintf(
        '#x%08x',
        unpack('N', $X)
    );

    print {$fh} "(assert (= x_word $x_value))\n";

    print {$fh} smt_trailing_zero_constraint($target_bits);

    print {$fh} "(check-sat)\n";
    print {$fh} "(exit)\n";

    close $fh;

    open my $z3, '-|', 'z3', '-smt2', $filename
        or die "Unable to execute Z3: $!\n";

    local $/;
    my $output = <$z3>;
    close $z3;

    return $output;
}

# ------------------------------------------------------------
# Verify the exact known result.
# ------------------------------------------------------------

my $sat_output = run_z3($actual_zero_bits);

diag("Z3 result for actual trailing-zero count:");
diag($sat_output);

like(
    $sat_output,
    qr/^sat$/m,
    'Z3 accepts the actual digest trailing-zero count'
);

# ------------------------------------------------------------
# Verify that one additional bit is rejected.
# ------------------------------------------------------------

SKIP: {
    skip 'A 256-bit zero digest has no stronger constraint', 1
        if $actual_zero_bits == 256;

    my $unsat_output = run_z3($actual_zero_bits + 1);

    diag("Z3 result for one additional trailing-zero bit:");
    diag($unsat_output);

    like(
        $unsat_output,
        qr/^unsat$/m,
        'Z3 rejects one more trailing-zero bit'
    );
}

done_testing();

