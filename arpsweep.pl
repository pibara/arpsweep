#!/usr/bin/perl
# arpsweep.pl 0.1.0 Simple tool for ARP scanning a subnet.
# This script is a byproduct of the way-back filter project.
# copyright Rob J Meijer 3 nov 2002 rmeijer@xs4all.nl
# 
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
use English;
use Net::RawIP; 
use Net::Pcap;
use Socket;
sub childhnd {
  exit;
}
$arp=new Net::RawIP;
$bcmac="FF:FF:FF:FF:FF:FF";
$dev=$ARGV[0];
$|=1;
unless ($dev)
{
  $dev="eth0";
}
open(IFCFG,"/sbin/ifconfig $dev|") or die "Can't run: /sbin/ifconfig $dev";
while (<IFCFG>)
{
  if (/HWaddr\s+(\w\w:\w\w:\w\w:\w\w:\w\w:\w\w)/i) {$hwmac=$1;}
  if (/Mask:255\.255\.255\.\d+/) 
  {  
    $maskok=1; 
    if (/inet addr:(\d+\.\d+\.\d+\.(\d+))/i) {$myipasc=$1; $iplast=$2;}
    $maxip=256-2;
    $sdelay=0.001;
  }
  elsif (/Mask:255\.255\.\d+\.\d+/)
  {
    $maskok=1; 
    if (/inet addr:(\d+\.\d+\.(\d+)\.(\d+))/i) {$myipasc=$1; $iplast=$2*256+$3;}
    $maxip=256*256-2;
    $sdelay=0; #It takes to long to wait.
  }
}
close(IFCFG);
unless ($maskok && $myipasc && $hwmac)
{
  print "Something not so usable about the ethernet device:\n";
  unless ($maskok) {print "  Mask should be 255.255.255.0 to be usable\n";}
  unless ($myipasc){print "  Device should have an IP adress\n";}
  unless ($hwmac)  {print "  I'm stupid, device should have a MAC adress\n";}
  print "This is a rather simple POC to proof the concept of wayback\n";
  print "filtering. It assumes a /24 or a /16 on $dev\n";
  exit;
}

$myip=unpack("N",inet_aton($myipasc));
$mynet=$myip-$iplast;
@hwmac=split(/:/,$hwmac);
foreach $index (0 .. 5) {$hwmac[$index]=hex("00$hwmac[$index]");}
$|=1;
$arp->ethnew($dev);
$arp->ethset(dest => $bcmac);
$arppl1=pack("nnnCCnCCCCCCNnN",2054,1,2048,6,4,1,@hwmac,$myip,0,0);
$delay=$sdelay;
$pcap_t = Net::Pcap::open_live($dev, 42, 0, 10, \$err);
if (!defined($pcap_t)) {
   print "Oops, it seems I can't open $dev, open said: $err\n";
   exit;
}
#All we can handle is plain old Ethernet
if (Net::Pcap::datalink($pcap_t) !=1)
{
  print "The device $dev is no Ethernet\n";
  exit;
}
if (Net::Pcap::compile($pcap_t,\$filtert,'arp',1,0)== -1)
{
  print "Problem compiling filter\n";
  exit;
}
Net::Pcap::setfilter($pcap_t, $filtert);
$SIG{'CHLD'}='childhnd';
if ($pid = fork())
{
    while(1)
    {
      if ($pkt = Net::Pcap::next($pcap_t, \%hdr))
      {
         @af=unpack("CCCCCCCCCCCCnnnCCnCCCCCCNCCCCCCN",$pkt);
         @macdst=($af[0],$af[1],$af[2],$af[3],$af[4],$af[5]);
         @macsrc=($af[6],$af[7],$af[8],$af[9],$af[10],$af[11]);
         $proto=$af[12];
         $hwas=$af[13];
         $pas=$af[14];
         $hwal=$af[15];
         $pal=$af[16];
         $opcode=$af[17];
         @macsrc2=($af[18],$af[19],$af[20],$af[21],$af[22],$af[23]);
         $srcip=$af[24];
         @macdst2=($af[25],$af[26],$af[27],$af[28],$af[29],$af[30]);
         $dstip=$af[31];
         if ($proto==2054 && $hwas==1 && $pas==2048 && $hwal==6 && $pal==4 && $opcode==2)
         {
            $ip=inet_ntoa(pack("N",$srcip));
            foreach $index (0 .. 5) {$macsrc2[$index]=sprintf("%x",$macsrc2[$index]);}
            foreach $index (0 .. 5) {$macsrc[$index]=sprintf("%x",$macsrc[$index]);}
            $mac1=join(":",@macsrc);
            $mac2=join(":",@macsrc2);
            if ($mac1 eq $mac2)
            {
              print "$ip = $mac1\n";
            }
            else
            {
             print "SPOOF: $ip = $mac2 from $mac1\n";
            }
         }
      }
    }
}
unless (defined $pid)
{
    print "FORK ERROR\n";
    exit;
}
foreach $scan (1 .. $maxip)
{
    $scanip=$mynet+$scan;
    $arppl2=pack("N",$scanip);
    $arppl=$arppl1 . $arppl2;
    $arp->send_eth_frame($arppl,$delay,1);
}
sleep(1);
