package Digest::Adler32;

use strict;
use vars qw(@ISA);
require Digest::Base;
@ISA=qw(Digest::Base);

sub new
{
    my $class = shift;
    my $adler_state = 1;
    return bless \$adler_state, $class;
}

# Based on Generic C implementation at:
#  http://www.geocities.com/manuelkasper/prog/adler32.html

sub add
{
    my $self = shift;
    for my $buf (@_) {
	my $s1 = $$self & 0x0000FFFF;
	my $s2 = ($$self >> 16) & 0x0000FFFF;

	for (unpack("C", $buf)) {
	    $s1 += $_;
	    $s1 -= 65521 if $s1 > 65521;
	    $s2 += $s1;
	    $s2 -= 65521 if $s2 > 65521;
	    $$self = ($s2 << 16) + $s1;
	}
    }
    return $self;
}

sub digest
{
    my $self = shift;
    return pack("N", $$self);
}

1;
