#  Copyright (C) 2010  Stanislav Sinyagin
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

# $Id: M_net.pm 871 2010-08-13 20:52:20Z ssinyagin $
# Stanislav Sinyagin <ssinyagin@yahoo.com>

# CA Spectrum integration

package Torrus::DevDiscover::SpectrumDevices;

use strict;
use JSON;
use IO::File;
use Net::hostent;
use Socket;

use Torrus::Log;


$Torrus::DevDiscover::registry{'SpectrumDevices'} = {
    'sequence'     => 600,
    'checkdevtype' => \&checkdevtype,
    'discover'     => \&discover,
    'buildConfig'  => \&buildConfig
    };


# CA Spectrum-specific nodeid values are only assinged to IF-MIB interfaces
# of specific ifType. This is related to the fact that some Cisco virtual
# interfaces (such as MPLS layer) have non-unique ifName, and Spectrum uses
# ifName for interface reference.
# spectrum-ddcfg.pl applies default values, and additional
# values can be added in devdiscover-siteconfig.pl
# see IANAifType-MIB.my for values
our %onlyIfTypes;

# Blacklist of devtypes where Spectrum plugin would automatically skip
# its processing. spectrum-ddcfg.pl applies default values, and additional
# values can be added in devdiscover-siteconfig.pl
our %excludeDevtypes;


sub checkdevtype
{
    my $dd = shift;
    my $devdetails = shift;

    if( $devdetails->param('SpectrumDevices::manage') eq 'yes' )
    {
        foreach my $devtype (keys %excludeDevtypes)
        {
            if( $devdetails->isDevType($devtype) )
            {
                Info($devdetails->param('snmp-host') .
                     ': Device is of type ' . $devtype . ', which is listed ' .
                     'in Spectrum plugin blacklist. Skipping Spectrum ' .
                     'processing');
                return 0;
            }
        }
        
        my $data = $devdetails->data();
        
        if( $devdetails->hasCap('nodeidReferenceManaged') )
        {
            Error($devdetails->param('snmp-host') .
                  ': SpectrumDevices conflicts with ' .
                  $data->{'nodeidManagedBy'} . ' in nodeid management. ' .
                  'Modify the discovery instructions to enable only one of ' .
                  'the modules to manage nodeid.');
            return 0;
        }

        $devdetails->setCap('nodeidReferenceManaged');
        $data->{'nodeidManagedBy'} = 'SpectrumDevices';
        
        return 1;
    }

    return 0;
}


# We only read every export file once
my %export_cache;
my %cache_by_ip;


sub discover
{
    my $dd = shift;
    my $devdetails = shift;

    my $session = $dd->session();
    my $data = $devdetails->data();


    my $export_file = $devdetails->param('SpectrumDevices::export-file');
    if( not defined($export_file) )
    {
        Error('Mandatory parameter SpectrumDevices::export-file is not ' .
              ' defined for ' . $devdetails->param('snmp-host'));
        return 0;
    }
    
    if( not defined($export_cache{$export_file}) )
    {
        my $fh = new IO::File( $export_file, 'r' );
        if( not defined($fh) )
        {
            Error('Torrus::DevDiscover::SpectrumDevices cannot read ' .
                  $export_file . ': ' . $!);
            return 0;
        }

        my $json = new JSON;
        local $/;
        my $json_data = <$fh>;
        $fh->close();        
        my $result = eval { $json->decode( $json_data ) };
        if( not defined( $result ) )
        {
            Error('Error reading JSON contrent from ' . $export_file . ': ' .
                  $@);
            return 0;
        }

        $export_cache{$export_file} = $result;
        foreach my $mh ( keys %{$result} )
        {
            foreach my $attr ( 'IfModelNameOption', 
                               'IfModelNameOptionSecondary',
                               'MName',
                               'Network_Address' )
            {
                if( not defined( $result->{$mh}->{$attr} ) )
                {
                    Error('Mandatory attribute ' . $attr . ' is not defined ' .
                          'in ' . $export_file . ' for ' . $mh);
                    return 0;
                }
            }
                       
            my $ipaddr = $result->{$mh}->{'Network_Address'};
            $cache_by_ip{$export_file}{$ipaddr} = $mh;
        }
    }

    my $spectrum_data = $export_cache{$export_file};

    # We've got the Spectrum database export. Now find our device in Spectrum

    my $mh;
    
    # first check if any of these parameters matches MH
    foreach my $param ( 'SpectrumDevices::device-mh',
                        'nodeid-device',
                        'system-id' )
    {
        my $val = $devdetails->param( $param );
        if( defined( $val ) and defined $spectrum_data->{$val} )
        {
            $mh = $val;
            Debug('Found the exact match of MH in ' . $param . ' for ' .
                  $devdetails->param('snmp-host') . ' in Spectrum data: ' .
                  'mh=' . $mh);
            last;
        }
    }

    if( not defined($mh) )
    {
        Debug('Trying to match the device IP address against Spectrum data');
        
        # now try to match the IP address
        # if SNMP host starts with a nondigit, consider it a DNS name
        
        my $hostname = $devdetails->param('snmp-host');

        if( $hostname =~ /^\d/o )
        {
            $mh = $cache_by_ip{$export_file}{$hostname};
        }
        else
        {
            my $domain = $devdetails->param('domain-name');
            if( $domain and index($hostname, '.') < 0 and
                index($hostname, ':') < 0 )
            {
                $hostname .= '.' . $domain;
            }
            
            my $h = gethost($hostname);
            if( not defined( $h ) )
            {
                Error('Cannot resolve DNS name: ' . $hostname);
                return 0;
            }

            foreach my $addr ( @{$h->addr_list()} )
            {
                my $ipaddr = inet_ntoa($addr);
                Debug('Resolved hostname ' . $hostname . ' into ' . $ipaddr);
                $mh = $cache_by_ip{$export_file}{$ipaddr};
                if( defined( $mh ) )
                {
                    Debug('IP address ' . $ipaddr . ' matched mh=' . $mh);
                    last;
                }
            }
        }
    }
    
    if( not defined($mh) )
    {
        Error('Cannot find ' . $devdetails->param('snmp-host') .
              ' in Spectrum export file ' . $export_file . '. Falling back ' .
              ' to the original nodeid scheme');
        return 1;
    }

    # Now we matched the current device with the Spectrum MH
    Debug('Found Spectrum MH: ' . $mh);

    # Copy the old nodeid values into a new reference map
    my $orig_nameref_ifNodeidPrefix =
        $data->{'nameref'}{'ifNodeidPrefix'};
    my $orig_nameref_ifNodeid =
        $data->{'nameref'}{'ifNodeid'};

    $data->{'nameref'}{'ifNodeidPrefix'} = 'Spectrum_ifNodeidPrefix';
    $data->{'nameref'}{'ifNodeid'} = 'Spectrum_ifNodeid';

    foreach my $ifIndex ( keys %{$data->{'interfaces'}} )
    {
        my $interface = $data->{'interfaces'}{$ifIndex};
        next if $interface->{'excluded'};

        $interface->{$data->{'nameref'}{'ifNodeidPrefix'}} =
            $interface->{$orig_nameref_ifNodeidPrefix};
        
        $interface->{$data->{'nameref'}{'ifNodeid'}} =
            $interface->{$orig_nameref_ifNodeid};
    }

    my $ifnameref_primary = $spectrum_data->{$mh}{'IfModelNameOption'};
    my $ifnameref_secondary =
        $spectrum_data->{$mh}{'IfModelNameOptionSecondary'};
    my $mname = $spectrum_data->{$mh}{'MName'};

    $data->{'param'}{'nodeid-device'} = $mname;
    $data->{'param'}{'spectrum-device-mh'} = $mh;

    foreach my $ifIndex ( keys %{$data->{'interfaces'}} )
    {
        my $interface = $data->{'interfaces'}{$ifIndex};        
        next if $interface->{'excluded'};
        next unless $onlyIfTypes{$interface->{'ifType'}};
            
        $interface->{$data->{'nameref'}{'ifNodeidPrefix'}} =
            'spec-if//' . $mname . '_';
        
        my $ifname = $interface->{$ifnameref_primary};
        if( not defined( $ifname ) )
        {
            Error('Cannot find ' . $ifnameref_primary .
                  ' for ifIndex=' . $ifIndex);
            return 0;
        }

        if( length( $ifnameref_secondary ) )
        {
            my $ifname_sec = $interface->{$ifnameref_secondary};
            if( not defined( $ifname_sec ) )
            {
                Error('Cannot find ' . $ifnameref_secondary .
                      ' for ifIndex=' . $ifIndex);
                return 0;
            }
            
            $ifname .= '_' . $ifname_sec;
        }
            
        $interface->{$data->{'nameref'}{'ifNodeid'}} = $ifname;            
    }
    
    return 1;
}


sub buildConfig
{
    my $devdetails = shift;
    my $cb = shift;
    my $devNode = shift;

    my $data = $devdetails->data();
}



1;


# Local Variables:
# mode: perl
# indent-tabs-mode: nil
# perl-indent-level: 4
# End:
