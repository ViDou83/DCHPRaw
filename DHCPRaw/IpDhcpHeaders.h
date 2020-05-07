#pragma once

#define NUMBER_DHCP_MSG_LIST 9

/*typedef __int32 int32_t;
typedef unsigned __int32 u_int32_t;
typedef __int16 int16_t;
typedef unsigned __int16 u_int16_t;
typedef __int8 int8_t;
typedef unsigned __int8 u_int8_t;
typedef UCHARu_char;
*/
#define MAX_BUFFER 1480

/*
######################################################################################################################################
*/
#define DHCP_UDP_CPORT 68
#define DHCP_UDP_SPORT 67
#define DHCP_REQUEST 0x1
#define DHCP_REPLY   0x2
#define DHCP_MAGIC           0x63825363//      0x63538263
#define BOOTP_MIN_LEN        0x12c
#define DHCP_PAD             0x00
#define DHCP_SUBNETMASK      0x01
#define DHCP_TIMEOFFSET      0x02
#define DHCP_ROUTER          0x03
#define DHCP_TIMESERVER      0x04
#define DHCP_NAMESERVER      0x05
#define DHCP_DNS             0x06
#define DHCP_LOGSERV         0x07
#define DHCP_COOKIESERV      0x08
#define DHCP_LPRSERV         0x09
#define DHCP_IMPSERV         0x0a
#define DHCP_RESSERV         0x0b
#define DHCP_HOSTNAME        0x0c
#define DHCP_BOOTFILESIZE    0x0d
#define DHCP_DUMPFILE        0x0e
#define DHCP_DOMAINNAME      0x0f
#define DHCP_SWAPSERV        0x10
#define DHCP_ROOTPATH        0x11
#define DHCP_EXTENPATH       0x12
#define DHCP_IPFORWARD       0x13
#define DHCP_SRCROUTE        0x14
#define DHCP_POLICYFILTER    0x15
#define DHCP_MAXASMSIZE      0x16
#define DHCP_IPTTL           0x17
#define DHCP_MTUTIMEOUT      0x18
#define DHCP_MTUTABLE        0x19
#define DHCP_MTUSIZE         0x1a
#define DHCP_LOCALSUBNETS    0x1b
#define DHCP_BROADCASTADDR   0x1c
#define DHCP_DOMASKDISCOV    0x1d
#define DHCP_MASKSUPPLY      0x1e
#define DHCP_DOROUTEDISC     0x1f
#define DHCP_ROUTERSOLICIT   0x20
#define DHCP_STATICROUTE     0x21
#define DHCP_TRAILERENCAP    0x22
#define DHCP_ARPTIMEOUT      0x23
#define DHCP_ETHERENCAP      0x24
#define DHCP_TCPTTL          0x25
#define DHCP_TCPKEEPALIVE    0x26
#define DHCP_TCPALIVEGARBAGE 0x27
#define DHCP_NISDOMAIN       0x28
#define DHCP_NISSERVERS      0x29
#define DHCP_NISTIMESERV     0x2a
#define DHCP_VENDSPECIFIC    0x2b
#define DHCP_NBNS            0x2c
#define DHCP_NBDD            0x2d
#define DHCP_NBTCPIP         0x2e
#define DHCP_NBTCPSCOPE      0x2f
#define DHCP_XFONT           0x30
#define DHCP_XDISPLAYMGR     0x31
#define DHCP_REQUESTEDIP     0x32
#define DHCP_LEASETIME       0x33
#define DHCP_OPTIONOVERLOAD  0x34
#define DHCP_MESSAGETYPE     0x35
#define DHCP_SERVIDENT       0x36
#define DHCP_PARAMREQUEST    0x37
#define DHCP_MESSAGE         0x38
#define DHCP_MAXMSGSIZE      0x39
#define DHCP_RENEWTIME       0x3a
#define DHCP_REBINDTIME      0x3b
#define DHCP_CLASSSID        0x3c
#define DHCP_CLIENTID        0x3d
#define DHCP_NISPLUSDOMAIN   0x40
#define DHCP_NISPLUSSERVERS  0x41
#define DHCP_MOBILEIPAGENT   0x44
#define DHCP_SMTPSERVER      0x45
#define DHCP_POP3SERVER      0x46
#define DHCP_NNTPSERVER      0x47
#define DHCP_WWWSERVER       0x48
#define DHCP_FINGERSERVER    0x49
#define DHCP_IRCSERVER       0x4a
#define DHCP_STSERVER        0x4b
#define DHCP_STDASERVER      0x4c
#define DHCP_FQDN            0x51
#define DHCP_LINKSEL         0x52
#define DHCP_SUBSEL			 0x76 
#define DHCP_END             0xff
#define DHCP_MSGDISCOVER     0x01
#define DHCP_MSGOFFER        0x02
#define DHCP_MSGREQUEST      0x03
#define DHCP_MSGDECLINE      0x04
#define DHCP_MSGACK          0x05
#define DHCP_MSGNACK         0x06
#define DHCP_MSGRELEASE      0x07
#define DHCP_MSGINFORM       0x08
/*
* FQDN options flags
*/
#define FQDN_N_FLAG   0x08
#define FQDN_E_FLAG   0x04
#define FQDN_O_FLAG   0x02
#define FQDN_S_FLAG   0x01

#define FQDN_MBZ_FLAG   0x0

/*
*  DHCP header
*  Dynamic Host Configuration Protocol
*  Static header size: f0 bytes
*/
//typedef struct dhcpv4_hdr
typedef struct _DHCPv4_HDR
{
	BYTE	dhcp_opcode;     /* opcode */
	BYTE	dhcp_htype;      /* hardware address type */
	BYTE	dhcp_hlen;       /* hardware address length */
	BYTE	dhcp_hopcount;   /* used by proxy servers */
	DWORD	dhcp_xid;        /* transaction ID */
	WORD	dhcp_secs;      /* number of seconds since trying to bootstrap */
	WORD	dhcp_flags;     /* flags for DHCP, unused for BOOTP */
	ULONG	dhcp_cip;        /* client's IP */
	ULONG	dhcp_yip;        /* your IP */
	ULONG	dhcp_sip;        /* server's IP */
	ULONG	dhcp_gip;        /* gateway IP */
	BYTE	dhcp_chaddr[16]; /* client hardware address */
	//u_int8_t dhcp_chaddr_padding[10]; /* client hardware address padding */
	BYTE	dhcp_sname[64];  /* server host name */
	BYTE	dhcp_file[128];  /* boot file name */
	ULONG	dhcp_magic;      /* BOOTP magic header */
} DHCPv4_HDR, * pDHCPv4_HDR;
/*
*  Custom DHCP option struct
*/
typedef struct DHCP_OPT {
	BYTE OptionType;
	BYTE OptionLength;
	BYTE* OptionValue;
} DHCP_OPT, * PDHCP_OPT;

#define MAX_CUSTOM_DHCP_OPTIONS 64
#define DHCP_OPT_HARDWARE_TYPE 0x01

/*
* For Custom DHCP options
* Static arrays for custom_dhcp_option_hdr
*/
//UINT8 no_custom_dhcp_options = { 0 };

// IPv4 headers
typedef struct _IPv4_HDR
{
	UCHAR ip_verlen;        // 4-bit IPv4 version
									 // 4-bit header length (in
									 // 32-bit words)
	UCHAR	ip_tos;           // IP type of service
	USHORT	ip_totallength;   // Total length
	USHORT	ip_id;            // Unique identifier
	USHORT	ip_offset;        // Fragment offset field
	UCHAR	ip_ttl;           // Time to live
	UCHAR	ip_protocol;      // Protocol(TCP,UDP etc)
	USHORT	ip_checksum;      // IP checksum
	UINT	ip_srcaddr;       // Source address
	UINT	ip_destaddr;      // Source address
} IPv4_HDR, * pIPv4_HDR, FAR* lpIPv4_HDR;

// Define the UDP header
typedef struct UDPv4_HDR
{
	USHORT	src_port;       // Source port no.
	USHORT	dst_port;       // Dest. port no.
	USHORT	udp_length;       // Udp packet length
	USHORT	udp_checksum;     // Udp checksum (optional)
} UDPv4_HDR, * pUDPv4_HDR;


#define DHCP_BROADCAST_FLAG 0x1 /* DHCP broadcast flag */
#define DHCP_UNICAST_FLAG 0x0 /* DHCP broadcast flag */

#define ETHER_H		0x10	/* Ethernet header: 14 bytes */
#define ETHER_ADDR_LEN  0x6	/* Ethernet address len: 6 bytes */	
#define IP_ADDR_LEN	0x4
#define VLAN_H		0x12	/* Ethernet header + vlan header*/	
#define IP_H		0x20	/* IP header: 20 bytes */	
#define UDP_H		0x8	/* UDP header: 8 bytes */		
#define ICMP_H		0x8
#define ICMP_PAYLOAD	0x3c	/* 60 bytes of ICMP payload */
#define DHCPv4_H	0xf0    /**< DHCP v4 header:     240 bytes */
#define ARP_H_LEN	0x08

#define DHCP_MIN_PACKET_SIZE 272
#define DHCP_MAX_PACKET_SIZE 576

//#########################################################################################

#define MAX_DHCP_CLIENTS 150