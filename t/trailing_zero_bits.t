
use strict;
use warnings;
use Test::More;

use lib 'lib';

use SHA256::Reverse qw(
    has_trailing_zero_bits
);

# A digest ending in four zero bytes.
my $digest_32 = ("\xAA" x 28) . "\x00\x00\x00\x00";

ok(
    has_trailing_zero_bits($digest_32, 32),
    'Recognizes 32 trailing zero bits'
);

ok(
    has_trailing_zero_bits($digest_32, 24),
    'Recognizes 24 trailing zero bits'
);

ok(
    has_trailing_zero_bits($digest_32, 1),
    'Recognizes at least one trailing zero bit'
);

ok(
    has_trailing_zero_bits($digest_32, 0),
    'Zero-bit requirement always succeeds'
);

# Partial-byte checks.
my $partial_4 = ("\xAA" x 31) . "\xF0";

ok(
    has_trailing_zero_bits($partial_4, 4),
    'Recognizes four trailing zero bits'
);

ok(
    !has_trailing_zero_bits($partial_4, 5),
    'Rejects five trailing zero bits'
);

my $partial_7 = ("\xAA" x 31) . "\x80";

ok(
    has_trailing_zero_bits($partial_7, 7),
    'Recognizes seven trailing zero bits'
);

ok(
    !has_trailing_zero_bits($partial_7, 8),
    'Rejects eight trailing zero bits'
);

# Nonzero trailing byte.
my $nonzero = ("\xAA" x 31) . "\x01";

ok(
    !has_trailing_zero_bits($nonzero, 1),
    'Rejects digest with final bit set'
);

ok(
    !has_trailing_zero_bits($nonzero, 8),
    'Rejects nonzero final byte'
);

# Entire digest.
my $all_zero = "\x00" x 32;

ok(
    has_trailing_zero_bits($all_zero, 256),
    'Recognizes 256 trailing zero bits'
);

ok(
    !has_trailing_zero_bits($digest_32, 256),
    'Rejects digest that is not entirely zero'
);

# Invalid inputs.
my $short_digest = "\x00" x 31;

eval {
    has_trailing_zero_bits($short_digest, 8);
};

like(
    $@,
    qr/Digest must be exactly 32 bytes/,
    'Rejects digest of incorrect length'
);

eval {
    has_trailing_zero_bits($digest_32, 257);
};

like(
    $@,
    qr/Bit count must be between 0 and 256/,
    'Rejects bit count greater than 256'
);

eval {
    has_trailing_zero_bits($digest_32, -1);
};

like(
    $@,
    qr/Bit count must be between 0 and 256/,
    'Rejects negative bit count'
);

done_testing();

