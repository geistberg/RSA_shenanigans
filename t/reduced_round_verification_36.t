use strict;
use warnings;

use Test::More;
use lib 'lib';

use SHA256::Reverse qw(
    double_sha256_reduced
    has_trailing_zero_bits
);

my $b = pack("C*", 0 .. 79);
my $x = pack("H*", "7e1fafc4");

my $digest = double_sha256_reduced(
    $b,
    $x,
    36,
    36
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
