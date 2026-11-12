
use strict;
use warnings;

use Test::More;
use lib 'lib';

use SHA256::Reverse qw(
    double_sha256_reduced
    has_trailing_zero_bits
);

# Recreate the exact B.bin used in our solver experiment.
my $b = pack("C*", 0 .. 79);

# Candidate found by Z3 at 16 inner / 16 outer rounds.
my $x = pack("H*", "d35259a9");

my $digest = double_sha256_reduced(
    $b,
    $x,
    16,
    16
);

diag("Reduced-round digest: " . unpack("H*", $digest));

is(
    length($digest),
    32,
    "Reduced-round digest is 32 bytes"
);

ok(
    has_trailing_zero_bits($digest, 4),
    "Candidate has at least 4 trailing zero bits"
);

done_testing();

