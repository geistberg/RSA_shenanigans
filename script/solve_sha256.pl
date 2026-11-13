
#!/usr/bin/env perl

use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../lib";

use Digest::SHA qw(sha256);
use File::Temp qw(tempfile);
use Time::HiRes qw(time);

use SHA256::Reverse qw(
    smt_double_hash
    smt_trailing_zero_constraint
    has_trailing_zero_bits
);

# ------------------------------------------------------------
# Arguments
# ------------------------------------------------------------

my ($b_file, $target_bits, $timeout_ms, $inner_rounds, $outer_rounds) = @ARGV;

die "Usage: perl script/solve_sha256.pl B.bin trailing_zero_bits [timeout_ms] [inner_rounds] [outer_rounds]\n"
    unless defined $b_file && defined $target_bits;

$timeout_ms   = 120000 unless defined $timeout_ms;
$inner_rounds = 64 unless defined $inner_rounds;
$outer_rounds = 64 unless defined $outer_rounds;

die "Invalid inner round count\n"
    unless $inner_rounds =~ /^\d+$/
        && $inner_rounds >= 1
        && $inner_rounds <= 64;

die "Invalid outer round count\n"
    unless $outer_rounds =~ /^\d+$/
        && $outer_rounds >= 1
        && $outer_rounds <= 64;

die "Trailing-zero bits must be an integer from 1 to 256\n"
    unless $target_bits =~ /^\d+$/
        && $target_bits >= 1
        && $target_bits <= 256;

$timeout_ms = 120000 unless defined $timeout_ms;

die "Timeout must be a positive integer\n"
    unless $timeout_ms =~ /^\d+$/
        && $timeout_ms > 0;

# ------------------------------------------------------------
# Read the known 80-byte B value
# ------------------------------------------------------------

open my $b_fh, '<', $b_file
    or die "Cannot open B file '$b_file': $!\n";

binmode $b_fh;

my $B;
{
    local $/;
    $B = <$b_fh>;
}

close $b_fh;

die "B must be exactly 80 bytes; found " . length($B) . "\n"
    unless defined($B) && length($B) == 80;

print "Inner rounds: $inner_rounds\n";
print "Outer rounds: $outer_rounds\n";
print "Input B: $b_file\n";
print "Target:  $target_bits trailing zero bits\n";
print "Timeout: $timeout_ms ms\n";
print "Building symbolic double-SHA-256 model...\n";

# ------------------------------------------------------------
# Generate the SMT-LIB problem
# ------------------------------------------------------------

my $start_time = time();

my $smt = smt_double_hash($B, $inner_rounds, $outer_rounds);

printf "Model generation time: %.2f seconds\n", time() - $start_time;

my ($smt_fh, $smt_file) = tempfile(
    SUFFIX => '.smt2',
    UNLINK => 1
);

print {$smt_fh} "(set-logic QF_BV)\n";
print {$smt_fh} "(set-option :produce-models true)\n";
print {$smt_fh} "(set-option :timeout $timeout_ms)\n";
print {$smt_fh} "(set-option :sat.random_seed 1)\n";
print {$smt_fh} "(set-option :smt.random_seed 1)\n";

print {$smt_fh} $smt;

# IMPORTANT:
# x_word is deliberately NOT assigned a known value.
# It is the unknown value we want Z3 to discover.

print {$smt_fh} smt_trailing_zero_constraint($target_bits);

print {$smt_fh} "(check-sat)\n";
print {$smt_fh} "(get-info :reason-unknown)\n";
print {$smt_fh} "(get-value (x_word))\n";

close $smt_fh
    or die "Unable to finish writing SMT-LIB file\n";

# ------------------------------------------------------------
# Execute Z3
# ------------------------------------------------------------

print "Asking Z3 to find X...\n";

my $z3_start_time = time();

open my $z3_fh, '-|', 'z3', '-st', '-smt2', $smt_file
    or die "Unable to execute Z3: $!\n";

my $output;
{
    local $/;
    $output = <$z3_fh>;
}

close $z3_fh;

printf "Z3 execution time: %.2f seconds\n", time() - $z3_start_time;

print "\nZ3 output:\n";
print $output;

# ------------------------------------------------------------
# Interpret solver result
# ------------------------------------------------------------

if ($output =~ /^unsat\b/m) {
    die "\nNo solution exists for this constraint and B.\n";
}

if ($output =~ /^unknown\b/m) {
    die "\nZ3 could not determine a result. It may have reached its timeout.\n";
}

die "\nZ3 did not report sat, unsat, or unknown.\n"
    unless $output =~ /^sat\b/m;

# ------------------------------------------------------------
# Extract the discovered 32-bit value
# ------------------------------------------------------------

my ($x_hex) = $output =~
    /\(x_word\s+#x([0-9a-fA-F]{8})\)/;

die "\nZ3 reported sat but did not return x_word.\n"
    unless defined $x_hex;

my $X = pack('H*', $x_hex);

print "\n";
print "========================================\n";
print "Z3 FOUND A SOLUTION\n";
print "========================================\n";
print "X (hex): $x_hex\n";
print "X (bytes): " . unpack('H*', $X) . "\n";

# ------------------------------------------------------------
# Independently verify the discovered value
# ------------------------------------------------------------

print "\nVerifying with Digest::SHA...\n";

# ------------------------------------------------------------
# Verify the discovered value
# ------------------------------------------------------------

if ($inner_rounds == 64 && $outer_rounds == 64) {

    print "\nVerifying full SHA-256 with Digest::SHA...\n";

    my $inner_digest = sha256($B . $X);
    my $final_digest = sha256($inner_digest);

    print "Inner digest: " . unpack('H*', $inner_digest) . "\n";
    print "Final digest: " . unpack('H*', $final_digest) . "\n";

    if (has_trailing_zero_bits($final_digest, $target_bits)) {
        print "\nSUCCESS: Independently verified!\n";
        print "The final digest has at least $target_bits trailing zero bits.\n";
    }
    else {
        die "\nVERIFICATION FAILED: Result did not satisfy the target.\n";
    }

}
else {
    print "\nREDUCED-ROUND EXPERIMENT\n";
    print "The candidate satisfies the reduced-round SMT model only.\n";
    print "It is NOT a verified full SHA-256 solution.\n";
}
