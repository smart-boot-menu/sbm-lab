use base 'basetest';
use strict;
use warnings;
use testapi;

sub run {
    # Wait for the sbm-lab UEFI probe to emit its boot and GOP markers on COM1.
    my $entry = wait_serial('SBM-LAB-MARKER:uefi-entry', 60);
    die 'Did not observe SBM-LAB-MARKER:uefi-entry on serial console' unless $entry;

    my $gop = wait_serial(qr/SBM-LAB-MARKER:gop-ready width=\d+ height=\d+/, 30);
    save_screenshot;
    die 'Did not observe SBM-LAB-MARKER:gop-ready on serial console' unless $gop;

    my $halt = wait_serial('SBM-LAB-MARKER:halt', 30);
    die 'Did not observe SBM-LAB-MARKER:halt on serial console' unless $halt;
}

sub test_flags {
    return { fatal => 1 };
}

1;
