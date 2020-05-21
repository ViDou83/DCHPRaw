# DCHPRaw
DCHP Raw socket C++ (relay and many options)

This progam allows to simulate the behavior of a DHCP Client and DHCP relays. This program can be only be run on Windows Server SKU as RAW socket support is needed.

DhcpRaw:
Version: 1.0
Author: Vincent Douhet <vidou@microsoft.com>
----------------------------------------------------------------
Usage:  regular mode:   DhcpRaw -i {ifIndex} -n {NbrLeasesWanted} -a
        Relay mode:     DhcpRaw -i {ifIndex} -n {NbrLeasesWanted} -r  {AddrIP} -s {AddrIP} -a
----------------------------------------------------------------
        -i: Specify the ifIndex of the NIC where you want to send out DHCP msg (please run DHCPRaw.exe -d
        -n: Number of DHCP leases you want to request
        -r: RELAY MODE ONLY: Address ip to borrow as DHCP relay. Alternate IP Address will be plumbed on the NIC specified by -i
        -s: RELAY MODE ONLY: Specify the ip address of the DHCP server to which relay (for fake) the DHCP messages. To allow the DHCP SRV to respond, please add a default route to this machine or a arp static entry
        -d: Dump all local system's adapters settings and attributes
        -a: Automatically send DHCP release for granted lease(s)
        -opt: Specify custom opt in Hex format seperate by ,;:/
                Ex for OPT 82 with SubnetSelection 192.168.100.0/24:
                        -opt 0x52,0x6,0x5,0x4,0xc0,0xa8,0x64,0x0
        -paramreqlist: Specify paramaters request list (DHCP opt 55) in Hex format separate by ,;:/.
                Ex SubnetMask,DomainName,Router,NetBIOSopts,DomainNameServer::
                        -paramreqlist 0x1,0xf,0x3,0x2c,0x2e,0x2f,0x6
