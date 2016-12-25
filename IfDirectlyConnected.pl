#!/usr/bin/perl

#
# Copyright (c) 2016 Wojciechowski Piotr
# https://facebook.com/Piotr.Wojciechowski.CCIE
# https://ccieplayground.wordpress.com/
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

use strict;
use warnings;
use boolean;

use REST::Client;
use MIME::Base64;
use JSON;
use JSON::XS 'decode_json';
use Data::Dumper;
use Data::Validate::IP qw(is_ipv4);
use Scalar::Util;
use Sub::Identify;

#allows JSON with boolean to display properly
$JSON::PP::true  = "true";
$JSON::PP::false = "false";

# Global variable matching managemen IP address with interface configured IP address
our %ManagementIPArray = (
    "10.0.12.1"   => "172.16.1.51",    # Device asav-1
    "10.0.13.1"   => "172.16.1.51",
    "10.100.15.1" => "172.16.1.51",
    "10.100.16.1" => "172.16.1.51",

    "10.0.12.2" => "172.16.1.52",      # Device asav-2
    "10.0.24.2" => "172.16.1.52",

    "10.0.34.3" => "172.16.1.53",      # Device asav-3
    "10.0.13.3" => "172.16.1.53",

    "10.0.34.4"   => "172.16.1.54",    # Device asav-4
    "10.0.24.4"   => "172.16.1.54",
    "10.100.47.4" => "172.16.1.54",
    "10.100.48.4" => "172.16.1.54",
);

# Function:	dprint()
# Argument:
# Return:
# Printing value with debug markers
sub dprint {
    print "\n\nD ==>\nLine: "
        . ( caller(0) )[2] . "\n"
        . $_[0]
        . "\n<== D\n\n";
}

# Function:	CheckIfRouteIsInRoutingTable()
# Argument:
# Return: 	boolean
# Checking if route is in table via ASA CLI command
sub CheckIfRouteIsInRoutingTable {
    if ( $_[0] =~ /not in table/ ) {
        return false;
    }
    else {
        return true;
    }
}

# Function:	ExecutePOSTMethod
# Argument:	Destination IP, URL, Data
# Return: 	scalar, integer
# Get management IP of device based on interface assigned address using %ManagementIPArray
sub ExecutePOSTMethod {
    my $DestinationIP = $_[0];
    my $url           = $_[1];
    my $data          = $_[2];

    # Configurables
    my $endpoint = "https://" . $DestinationIP;
    my $userpass = "cisco:cisco"
        ;  #default username and password... can be reset by command line args

    # Older implementations of LWP check this to disable server verification
    $ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;

    # Set up the connection
    my $client = REST::Client->new();

# disable server verification
# Try SSL_verify_mode => SSL_VERIFY_NONE.  0 is more compatible, but may be deprecated
    $client->getUseragent()->ssl_opts( SSL_verify_mode => 0 );

    $client->setHost($endpoint);
    $client->addHeader( "Authorization",
        "Basic " . encode_base64($userpass) );
    $client->addHeader( "Content-Type", "application/json" );

    $client->POST( $url, $data );

    return ( $client->responseContent(), $client->responseCode() );
}

# Function:	GetASARoutingTableEntry
# Argument:	Management IP, Checked IP
# Return: 	boolean
# Check if NetworkObject object exist
sub GetASARoutingTableEntry {
    my $ManagementIP     = $_[0];
    my $CheckedIPAddress = $_[1];

    my $data = '{
	  "commands": [
		"show route ' . $CheckedIPAddress . '"
	  ]
	}';

    my ( $NetworkObjectResponse, $NetworkObjectResponseCode )
        = ExecutePOSTMethod( $ManagementIP, "/api/cli", $data );

    if ( $NetworkObjectResponseCode == 404 ) {
        return false;
    }
    else {
        return $NetworkObjectResponse;
    }

}

# Function:	CheckIfRouteDirectlyConnected()
# Argument:
# Return: 	boolean
# Checking if route is in table via ASA CLI command
sub CheckIfRouteDirectlyConnected {
    if ( $_[0] =~ /directly connected/ ) {
        return true;
    }
    else {
        return false;
    }
}

# MAIN PROGRAM STARTS HERE!!

# Get arguments
my $MAINCheckedIPAddress = $ARGV[0];
my $MAINManagementIP     = $ARGV[1];

#Check number of arguments
if ( @ARGV != 2 ) {
    print
        "Usage: IfDirectlyConnected.pl <Checked IP Address> <Firewall Management IP>\n\n";
    exit;
}

#Execute CLI command and get "show route" from selected device
my $MAINRoutingEntryForCheckedIP
    = GetASARoutingTableEntry( $MAINManagementIP, $MAINCheckedIPAddress );

print "Checking address "
    . $MAINCheckedIPAddress
    . " on firewall "
    . $MAINManagementIP . "\n";

if ( CheckIfRouteIsInRoutingTable($MAINRoutingEntryForCheckedIP) ) {
    if ( CheckIfRouteDirectlyConnected($MAINRoutingEntryForCheckedIP) ) {
        print "RESULT: Destination route is directly connected\n\n";
    }
    else {
        print "RESULT: Route in routing table but not directly connected\n\n";
    }
}
else {
    print "RESULT: Subnet not in routing table\n\n";
}
