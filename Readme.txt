================================================================================
Scamp 0.3.4
Copyright ©2007-2008 Liam Kirton <liam@int3.ws>

7th April 2008
http://int3.ws/
================================================================================

=========
Overview:
=========

Scamp is a small ICMP scanner for Windows, built using Winpcap
(http://www.winpcap.org/), and designed for efficient parallel scanning of
network ranges.

===========
Parameters:
===========

/Device:
--------

The /Device parameter specifies the Winpcap device to use for scanning. Execute
Scamp.exe without parameters to view a list of available devices.

/Target:
--------

The /Target parameter may contain several disjoint target strings separated by
semi-colons, e.g. "host.domain.tld;a.b.c.d;x.y.z.w".

Each target string may contain a host name, or an IP address taking the form
"a.b.c.d".

Each octet of each target string may contain one or more comma separated digits
or ranges, e.g. "a-b,c.d-e,f.g,h.i-j".

Each target string parameter may also specify a subnet in VLSM/CIDR notation,
e.g. "a-b,c.d-e,f.g,h.i/x".

Additionally, a host name may be specified together with a subnet
(e.g. "host.domain.tld/24"). This will resolve via DNS to a.b.c.d/24 and hence
the relevant network segment will be scanned.

/Resolve:
---------

The /Resolve parameter specifies that target and intermediate IP addresses should
be resolved. This is done in parallel to the scan.

/Icmp:
------

The /Icmp parameter specifies the selection of ICMP queries to submit to each
given target. The value of this parameter should contain one or more from
"e", "i", "n", "t" (comma separated), corresponding to echo, information,
netmask and timestamp requests respectively.

/Trace:
-------

The /Trace parameter specifies that the route to each given target should be
traced. The value of this parameter should contain one or more from
"e", "t", "u" (comma separated), corresponding to ICMP echo request, TCP and UDP
route tracing respectively.

/Dport:
-------

This parameter specifies the destination port to which TCP and UDP route tracing
packets should be sent.

/Sport:
-------

This parameter specifies the source port from which TCP and UDP route tracing
packets should be sent. Use in conjunction with "/Trace u".

NOTE: "/Sport 53 /Dport 33434" specifies that the source port shall be fixed at
53, and the destination port shall increase from 33434. Similarly,
"/Dport 53 /Sport 33434" specifies that the destination port shall be fixed at
53, and the source port shall increase from 33434.

/Queue:
-------

The /Queue parameter specifies the maximum number of packets to send out in each
packet round.

Default: 1024.

/Block:
-------

The /Block parameter specifies the number of packets to send out in a block for
each target. Only one block per target is sent per packet round.

Default: 1.

/Interval:
----------

The /Interval parameter specifies the millisecond interval between each packet
round.

Default: 15.

/Retry:
-------

The /Retry parameter specifies the number of attempts at sending each packet.

Default: 0.

/Ip, /Netmask, /Route:
----------------------

The /Ip parameter specifies the source address from which outgoing packets are
sent, /Netmask specifies the subnet mask for this address, and /Route
specifies the default route to use.

Default: Adapter default.

/Dummy:
-------

The /Dummy parameter specifies that no actual scanning should occur, potential
scanning actions are reported.

=========
Examples:
=========

Basic Scans:
------------

Scamp.exe /Device 1 /Target host.domain.tld /Icmp e

Scamp.exe /Device 1 /Target 25.0.1.1 /Icmp e

Scamp.exe /Device 1 /Target 25.0.1.1 /Icmp e,i,n,t /Trace e

Parallel Scans:
---------------

Scamp.exe /Device 1 /Target 25.0.0.0/24 /Icmp e

Scamp.exe /Device 1 /Target 25.0-1.0-255.0-255 /Icmp e,i,n,t /Trace e

Scamp.exe /Device 1 /Target 25.0-1.0-255.0-255 /Icmp e,i,n,t /Trace u /Sport 53

Scamp.exe /Device 1 /Target 25.0-1.0-255.0-255 /Icmp e,i,n,t /Trace e,t,u /Dport 53

Advanced Parallel Scans:
------------------------

Scamp.exe /Device 1 /Target 25.0-1.0-15,18-25,254.0-5,10,254 /Icmp e

Scamp.exe /Device 1 /Target 25.0-1.0-15,18-25,254.0-5,10,254 /Icmp e
          /Interval 0

Scamp.exe /Device 1 /Target 25.0-1.0-15,18-25,254.0-5,10,254 /Icmp e
          /Interval 0 /Queue 2048 /Block 32

Scamp.exe /Device 1 /Target 25.0-1.0-15,18-25,254.0-5,10,254;25.254.0.0-251,254
          /Icmp e /IP 25.62.0.1 /Netmask 255.192.0.0 /Route 25.0.0.254
          
================================================================================
