use strict;
use warnings;

use Test::More;

use FindBin;
use lib "$FindBin::Bin/../lib";

use Digest::SHA qw(sha256 sha256_hex);

use SHA256::Reverse qw(
    sha256_raw
    double_sha256_custom
    trace_compression
    message_schedule
);

my @test_vectors = (
    "",
    "abc",
    "HelloWorld",
    "The quick brown fox jumps over the lazy dog",
    "A" x 100,
    "B" x 1000
);

for my $input (@test_vectors) {

    my $expected = sha256($input);
    my $actual = sha256_raw($input);

    is(
        $actual,
        $expected,
        "SHA-256 matches Digest::SHA for input length "
        . length($input)
    );
}

my $double_expected = sha256(sha256("HelloWorld"));

my $double_actual = double_sha256_custom("HelloWorld");

is(
    $double_actual,
    $double_expected,
    "Custom double SHA-256 matches Digest::SHA"
);

# Verify message schedule
my $block = "\0" x 64;

my $schedule = message_schedule($block);

is(
    scalar(@$schedule),
    64,
    "Message schedule contains 64 words"
);

# Verify compression trace
my $trace = trace_compression($block);

is(
    scalar(@{$trace->{rounds}}),
    64,
    "Compression trace contains 64 rounds"
);

is(
    scalar(@{$trace->{result}}),
    8,
    "Compression result contains 8 state words"
);

done_testing();

