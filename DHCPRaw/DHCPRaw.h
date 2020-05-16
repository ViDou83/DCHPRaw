// DHCPRaw.h7
#pragma once

#ifdef _DEBUG
#define DEBUG_PRINT printf
#else
#define DEBUG_PRINT
#endif

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_NON_CONFORMING_WCSTOK
#define _CRT_SECURE_NO_WARNINGS

#define INI_NBR_SECTIONS 3
#define INI_OPT_NBR_KEYS 7
#define INI_GEN_NBR_KEYS 6

#define DHCP_RETRANSMIT_TIMEOUT 5000
#define DHCP_RETRANSMIT_COUNT 4

#define DHCP_OPT_NBR_DISCVOVER 3
#define DHCP_OPT_NBR_RELEASE 3

#include <iostream>
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>   // Needed for _wtoi
#include <stdio.h>
#include <tchar.h>
#include <conio.h>
#include <ws2tcpip.h> //IP_HDRINCL is here
#include <iphlpapi.h>
#include <icmpapi.h>
#include <stdarg.h>
#include <Windows.h>
#include <string.h>
#include <VersionHelpers.h>
#include <stdarg.h>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <sstream>
#include <ctime>

#pragma comment(lib,"IPHLPAPI.lib")
#pragma comment(lib,"ws2_32.lib") //winsock 2.2 library
#pragma comment(lib,"winmm.lib")
#pragma comment(lib,"Kernel32.lib")

#include "IpDhcpHeaders.h"

using namespace std;

/* GLOBALS */
extern HANDLE g_hSocketWaitEvent;
extern CRITICAL_SECTION g_CS[DHCP_REPLY];
extern bool g_DhcpReceiverAlone;
extern bool g_DhcpAutoRelease;

/* UTILS FUNCTIONS */
pIPv4_HDR BuildIPv4Hdr(ULONG SrcIp, ULONG DstIp, USHORT ip_len, USHORT Proto);
pUDPv4_HDR BuildUDPv4Hdr(USHORT SrcPort, USHORT DstPort, USHORT udp_len);
USHORT build_option50_54(USHORT OptionType, ULONG RequestedIP, PDHCP_OPT DhcpOpt);
USHORT build_option53(USHORT MsgType, PDHCP_OPT DhcpOpt);
USHORT build_option_55(BYTE ParameterRequestList[], PDHCP_OPT DhcpOpt);
USHORT build_option_81(char* FQDN, PDHCP_OPT DhcpOpt);
USHORT build_option_61(PUCHAR MacAddr, PDHCP_OPT DhcpOpt);
bool IsIPv4AddrPlumbebOnAdapter(int IfIndex, char* IPv4);
DWORD ListAllAdapters();
DWORD MyEcho(char* IpAddr);
LARGE_INTEGER UnixTimeToFileTime(time_t t);
DWORD WaitOnTimer(HANDLE hTimer, time_t time, const char* Msg);

/*
https://tools.ietf.org/html/rfc2131#section-5
RFC 2131          Dynamic Host Configuration Protocol         March 1997


 --------                               -------
|        | +-------------------------->|       |<-------------------+
| INIT-  | |     +-------------------->| INIT  |                    |
| REBOOT |DHCPNAK/         +---------->|       |<---+               |
|        |Restart|         |            -------     |               |
 --------  |  DHCPNAK/     |               |                        |
	|      Discard offer   |      -/Send DHCPDISCOVER               |
-/Send DHCPREQUEST         |               |                        |
	|      |     |      DHCPACK            v        |               |
 -----------     |   (not accept.)/   -----------   |               |
|           |    |  Send DHCPDECLINE |           |                  |
| REBOOTING |    |         |         | SELECTING |<----+            |
|           |    |        /          |           |     |DHCPOFFER/  |
 -----------     |       /            -----------   |  |Collect     |
	|            |      /                  |   |       |  replies   |
DHCPACK/         |     /  +----------------+   +-------+            |
Record lease, set|    |   v   Select offer/                         |
timers T1, T2   ------------  send DHCPREQUEST      |               |
	|   +----->|            |             DHCPNAK, Lease expired/   |
	|   |      | REQUESTING |                  Halt network         |
	DHCPOFFER/ |            |                       |               |
	Discard     ------------                        |               |
	|   |        |        |                   -----------           |
	|   +--------+     DHCPACK/              |           |          |
	|              Record lease, set    -----| REBINDING |          |
	|                timers T1, T2     /     |           |          |
	|                     |        DHCPACK/   -----------           |
	|                     v     Record lease, set   ^               |
	+----------------> -------      /timers T1,T2   |               |
			   +----->|       |<---+                |               |
			   |      | BOUND |<---+                |               |
  DHCPOFFER, DHCPACK, |       |    |            T2 expires/   DHCPNAK/
   DHCPNAK/Discard     -------     |             Broadcast  Halt network
			   |       | |         |            DHCPREQUEST         |
			   +-------+ |        DHCPACK/          |               |
					T1 expires/   Record lease, set |               |
				 Send DHCPREQUEST timers T1, T2     |               |
				 to leasing server |                |               |
						 |   ----------             |               |
						 |  |          |------------+               |
						 +->| RENEWING |                            |
							|          |----------------------------+
							 ----------
		  Figure 5:  State-transition diagram for DHCP clients

*/

typedef struct _DHCP_PACKET {
	pDHCPv4_HDR m_pDhcpMsg;
	time_t m_ltime;
	int m_iSizeOpt;
	USHORT m_iNbrOpt;
	int m_iRetry; //
	PDHCP_OPT* m_ppDhcpOpt; // type->PDHCP_OTP
	HANDLE hCompletionEvent;	
}DHCP_PACKET, * pDHCP_PACKET;

typedef struct _DHCP_LEASE {
	pDHCP_PACKET m_pDhcpPacketAck; //The ACK Received associated to the lease
	time_t m_T1; //m_pDhcpPacketAck->m_ltime + lease_time/2
	time_t m_T2; //m_pDhcpPacketAck->m_ltime + lease_time * (87.5/100)
	time_t m_TEnd; //End of Lease
	int m_iClientID;
}DHCP_LEASE, * pDHCP_LEASE;

struct Hash{
public:
	size_t operator()(const pDHCP_PACKET a) const {
		return std::hash<int>()(a->m_pDhcpMsg->dhcp_xid);
	}
};

struct Equal{
public:
	bool operator()(const pDHCP_PACKET a, const pDHCP_PACKET b) const
	{
		return a->m_pDhcpMsg->dhcp_xid == b->m_pDhcpMsg->dhcp_xid;
	};
};

typedef std::unordered_set<pDHCP_PACKET, Hash, Equal> DhcpMsgQ;

enum StateTransition { Init = 0, Selecting, Requesting, Bound, Renewing, Rebinding, Releasing };

namespace DHCPRaw 
{

	//DHCPRawLease 
	class DHCPRawLease
	{

	public:
		/////////////////////
		/// Constructor
		/////////////////////
		DHCPRawLease()
		{
			;
		}
		DHCPRawLease(pDHCP_PACKET& pDhcpAck, pDHCP_PACKET& pDhcpRequest, int ClientId);
		/////////////////////
		/// Methods
		/////////////////////
		void print();
		//
		pDHCP_LEASE GetLease();

	private:
		/////////////////////
		/// attributes
		/////////////////////	
		pDHCP_LEASE m_pDhcpLease				= NULL;
		char m_LocalAddrIp[INET_ADDRSTRLEN]		= { 0 };
		char m_ServerAddrIp[INET_ADDRSTRLEN]	= { 0 };

		/////////////////////
		/// Methods
		/////////////////////
		void SetLease(pDHCP_PACKET& pDhcpAck, pDHCP_PACKET& pDhcpRequest, int ClientId);
		void DeleteLease();
	};

	//DHCPRawMessage
	class DHCPRawPacket
	{
		public:
			/////////////////////
			/// Constructor
			/////////////////////
			DHCPRawPacket()
			{
				//
			}
			DHCPRawPacket(BYTE(&dhcp_chaddr)[ETHER_ADDR_LEN]);
			DHCPRawPacket(BYTE(&dhcp_chaddr)[ETHER_ADDR_LEN], bool IsRealyOn, string RelayAddr, string SrvAddr);
			/////////////////////
			/// Methods
			/////////////////////
			void	print();
			HANDLE	Run();
			void	destroy();
			//
			pDHCP_PACKET	get_pDhcpPacket();
			pIPv4_HDR		get_pIPv4hdr();
			pUDPv4_HDR		get_pUDPv4hdr();
			pDHCPv4_HDR		get_pDhcpMsg();
			//PDHCP_OPT*		get_pDhcpOpts();

		private:
			/////////////////////
			/// attributes
			/////////////////////	
			pDHCP_PACKET	m_pDhcpPacket	= NULL;
			//pDHCP_PACKET	m_pDHCPv4_HDR	= NULL;
			pIPv4_HDR		m_pIPv4_HDR		= NULL;
			pUDPv4_HDR		m_pUDPv4_HDR	= NULL;

			/////////////////////
			/// Methods
			/////////////////////
			// Create pIPV4 and UDPv4 hearder
			DWORD SetDhcpMessage(BYTE dhcp_opcode, BYTE dhcp_flags, ULONG dhcp_gip, BYTE(&dhcp_chaddr)[ETHER_ADDR_LEN]);
			

	};

	//DHCPRawClient 
	class DHCPRawClient
	{

		public:
			/////////////////////
			/// Constructor
			/////////////////////
			DHCPRawClient()
			{
				;
			}
			//Regular DHCPRawClient Objects
			DHCPRawClient(int number, int ifindex, string ClientPrefixName, vector<string> StrCustomOpt);
			//Sender DHCPRawClient Objects
			DHCPRawClient(int number, bool isReceiver, bool bIsRealyOn);
			//Relay  DHCPRawClient Objects
			DHCPRawClient(int number, int ifindex, string ClientPrefixName, vector<string> StrCustomOpt, bool isRelayOn, string RelayAddr, string SrvAddr);
			/////////////////////
			/// Methods
			/////////////////////
			void print();
			//
			void Run();
			//

		private:
			/////////////////////
			/// attributes
			/////////////////////			
			enum	StateTransition { Init = 0, Selecting, Requesting, Bound, Renewing, Rebinding, Releasing };

			BYTE	m_MAC[ETHER_ADDR_LEN]{ 0,0,0,0,0,0 };
			int		m_IfIndex = 0;
			int		m_ClientNumber = 0;
			bool	m_IsReceiver = false;
			bool	m_IsOfferReceive = false;
			int		m_StateTransition = StateTransition::Init;
			bool	m_gRelayMode = FALSE;
			string	m_RelayAddr;
			string  m_SrvAddr;
			string	m_ClientNamePrefix;
			HANDLE	m_hTimer = NULL;
			int		m_numberOfCustomOpts = 0;

			DHCPRawPacket	m_DhcpRawPacket;
			DHCPRawLease	m_DhcpRawLease;
			//pDHCP_PACKET is the struct enqueued to the hashtable... DHCP Sender/receiver will then consume it.
			pDHCP_PACKET	m_pDhcpRequest	= NULL;
			pDHCP_PACKET	m_pDhcpOffer	= NULL;
			pDHCP_PACKET	m_pDhcpAck		= NULL;
			pDHCP_LEASE		m_pDhcpLease	= NULL;
			vector<PDHCP_OPT> m_pCustomDhcpOpts;
			/////////////////////
			/// Methods
			/////////////////////
			//Set MAC from getting underlying MAC address using IP HLP API
			DWORD setMAC();
			//
			/* DHCP Client Thread:
				* Wait DHCP Receiver to be readay 	
				* Sent DHCP Discover (pass it to relay by inserted it to the Queue if needed)
				* Consume any DHCP Offer and reply accordingly by a request
				* to the Q (do 3 restransmit)
			*/
			DWORD DhcpClient();
			DWORD DhcpReceiver();
			//
			DWORD SendDhcpRequest();
			DWORD SetDHCPRequestCompletionEvent(int bucket, pDHCP_PACKET Reply);
			DWORD SetStateTransition(int NewState);
			DWORD build_dhpc_request();
			//
			int getClientNumber();
			void ConvertStrOptToDhpOpt(vector<string> StrCustomOpt);
	};

}

//Utils
DWORD GetAdapterMacByIndex(int IfIndex, BYTE (&MAC)[ETHER_ADDR_LEN]);