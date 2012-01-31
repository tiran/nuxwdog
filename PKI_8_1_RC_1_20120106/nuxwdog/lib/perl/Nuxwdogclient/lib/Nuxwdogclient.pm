#
# --- BEGIN COPYRIGHT BLOCK ---
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.
#
# Copyright (C) 2009 Red Hat, Inc.
# All rights reserved.
# --- END COPYRIGHT BLOCK ---
#

package Nuxwdogclient;

use strict;
use warnings;
use Carp qw(:DEFAULT);

require Exporter;
use AutoLoader;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Nuxwdogclient ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	
);

our $VERSION = '0.01';

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.

    my $constname;
    our $AUTOLOAD;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    croak "&Nuxwdogclient::constant not defined" if $constname eq 'constant';
    my ($error, $val) = constant($constname);
    if ($error) { croak $error; }
    {
	no strict 'refs';
	# Fixed between 5.005_53 and 5.005_61
#XXX	if ($] >= 5.00561) {
#XXX	    *$AUTOLOAD = sub () { $val };
#XXX	}
#XXX	else {
	    *$AUTOLOAD = sub { $val };
#XXX	}
    }
    goto &$AUTOLOAD;
}

require XSLoader;
XSLoader::load('Nuxwdogclient', $VERSION);

# Preloaded methods go here.

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Nuxwdogclient - Perl extension for calling nuxwdog client code from libnuxwdog

=head1 SYNOPSIS

  use Nuxwdogclient;
  Use this code to call nuxwdog client code from libnuxwdog

=head1 DESCRIPTION

Perl extension for calling nuxwdog client code from libnuxwdog.

=head2 EXPORT

None by default.



=head1 SEE ALSO

=head1 AUTHOR

alee, E<lt>alee@redhat.comE<gt>

=head1 COPYRIGHT AND LICENSE

This program is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

Copyright (C) 2009 Red Hat, Inc.
All rights reserved.

=cut
