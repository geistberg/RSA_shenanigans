
use strict;
use warnings;

use Test::More;

use FindBin;
use lib "$FindBin::Bin/../lib";

use SHA256::Reverse qw(
    compress_block
    reverse_compress_block
    message_schedule
);

# Test using the standard SHA-256 initial state
my @initial = (
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
);

my $block = "A" x 64;

my $forward = compress_block(
    \@initial,
    $block
);

my $reverse = reverse_compress_block(
    $forward,
    $block,
    \@initial
);

is_deeply(
    $reverse,
    \@initial,
    "Complete 64-round compression reverses exactly"
);

# Test using a nonstandard initial state
my @custom_initial = (
    0x12345678,
    0xABCDEF01,
    0x87654321,
    0xDEADBEEF,
    0x10203040,
    0x50607080,
    0x90ABCDEF,
    0xFEDCBA98
);

my $custom_forward = compress_block(
    \@custom_initial,
    $block
);

my $custom_reverse = reverse_compress_block(
    $custom_forward,
    $block,
    \@custom_initial
);

is_deeply(
    $custom_reverse,
    \@custom_initial,
    "Compression reverses with custom initial state"
);

# Test multiple different message blocks
for my $test (1..100) {

    my $random_block = pack(
        "C*",
        map { int(rand(256)) } 1..64
    );

    my $forward_result = compress_block(
        \@initial,
        $random_block
    );

    my $reverse_result = reverse_compress_block(
        $forward_result,
        $random_block,
        \@initial
    );

    is_deeply(
        $reverse_result,
        \@initial,
        "Random block $test reverses exactly"
    );
}

done_testing();

