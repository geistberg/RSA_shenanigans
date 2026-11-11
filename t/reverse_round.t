use strict;
use warnings;

use Test::More;

use FindBin;
use lib "$FindBin::Bin/../lib";

use Digest::SHA qw(sha256);

use SHA256::Reverse qw(
    forward_round
    reverse_round
    verify_round
    double_sha256
);

# Generate random 32-bit words
sub random_word {
    return unpack("N", pack("NN", rand(4294967296), 0));
}

# Fixed test vector
my $state = [
    0x12345678,
    0xabcdef01,
    0x87654321,
    0xdeadbeef,
    0x10203040,
    0x50607080,
    0x90abcdef,
    0xfedcba98
];

my $w = 0xA5A5A5A5;
my $k = 0x428A2F98;

my $next = forward_round($state,$w,$k);
my $recovered = reverse_round($next,$w,$k);

is_deeply(
    $recovered,
    $state,
    "Fixed round reverses exactly"
);

# Randomized inversion tests
for my $test (1..10000) {

    my @random_state = map {
        random_word()
    } 1..8;

    my $random_w = random_word();
    my $random_k = random_word();

    my $original = \@random_state;

    my $forward = forward_round(
        $original,
        $random_w,
        $random_k
    );

    my $reverse = reverse_round(
        $forward,
        $random_w,
        $random_k
    );

    is_deeply(
        $reverse,
        $original,
        "Randomized round $test reverses exactly"
    );
}

# Double SHA-256 independent verification
my $input = "HelloWorld";

my $expected = sha256(sha256($input));
my $actual = double_sha256($input);

is(
    $actual,
    $expected,
    "Double SHA-256 agrees with Digest::SHA"
);

done_testing();

