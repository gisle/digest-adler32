package Digest::Adler32;

use strict;
use vars qw($VERSION @ISA);
$VERSION = '0.01';

require Digest::base;
@ISA=qw(Digest::base);

sub new
{
    my $class = shift;
    my $adler_state = 1;
    return bless \$adler_state, $class;
}

sub clone {
    my $self = shift;
    my $adler_state = $$self;
    return bless \$adler_state, ref($self);
}

# Based on RFC 1950 section 9

sub add {
    my $self = shift;
    for my $buf (@_) {
	my $s1 = $$self & 0x0000FFFF;
	my $s2 = ($$self >> 16) & 0x0000FFFF;

	for (unpack("C", $buf)) {
	    $s1 = ($s1 + $_ ) % 65521;
	    $s2 = ($s2 + $s1) % 65521;
	    $$self = ($s2 << 16) + $s1;
	}
    }
    return $self;
}

sub digest {
    my $self = shift;
    return pack("N", $$self);
}

1;
