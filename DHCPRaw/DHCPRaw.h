// DHCPRaw.h7
#pragma once

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_NON_CONFORMING_WCSTOK
#define _CRT_SECURE_NO_WARNINGS

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
#include <ntsecapi.h>
#include <mstcpip.h>

#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <sstream>
#include <ctime>
#include "IpDhcpHeaders.h"

#pragma comment(lib,"IPHLPAPI.lib")
#pragma comment(lib,"ws2_32.lib") //winsock 2.2 library
#pragma comment(lib,"winmm.lib")
#pragma comment(lib,"Kernel32.lib")

#ifdef _DEBUG
#define DEBUG_PRINT printf
#else
#define DEBUG_PRINT
#endif

#define INI_NBR_SECTIONS 3
#define INI_OPT_NBR_KEYS 7
#define INI_GEN_NBR_KEYS 6

#define DHCP_RETRANSMIT_TIMEOUT 5000
#define DHCP_RETRANSMIT_COUNT 4

#define DHCP_OPT_NBR_DISCVOVER 4

#define DHCP_OPT_NBR_RELEASE 3

#define FREE_IF_NOT_NULL(p)\
	if ( p != NULL) \
		free(p)

using namespace std;

/* GLOBALS */
extern HANDLE g_hSocketWaitEvent;
extern CRITICAL_SECTION g_CS[DHCP_REPLY];
extern bool g_DhcpReceiverAlone;
extern bool g_DhcpAutoRelease;
extern bool g_NoDhcpOptions;

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

struct Hash {
public:
	size_t operator()(const pDHCP_PACKET a) const {
		return std::hash<int>()(a->m_pDhcpMsg->dhcp_xid);
	}
};

struct Equal {
public:
	bool operator()(const pDHCP_PACKET a, const pDHCP_PACKET b) const
	{
		return a->m_pDhcpMsg->dhcp_xid == b->m_pDhcpMsg->dhcp_xid;
	};
};

typedef std::unordered_set<pDHCP_PACKET, Hash, Equal> DhcpMsgQ;

enum TransitionState { Init = 0, Selecting, Requesting, Bound, Renewing, Rebinding, Releasing };


/* UTILS FUNCTIONS */
pIPv4_HDR Build_IPv4Hdr(ULONG SrcIp, ULONG DstIp, USHORT ip_len, USHORT Proto);
pUDPv4_HDR Build_UDPv4Hdr(USHORT SrcPort, USHORT DstPort, USHORT udp_len);
USHORT Build_DHCPOpt_50_54(USHORT OptionType, ULONG RequestedIP, PDHCP_OPT DhcpOpt);
USHORT Build_DHCPOpt_53(USHORT MsgType, PDHCP_OPT DhcpOpt);
USHORT Build_DHCPOpt_55(vector<int> ParameterRequestList, PDHCP_OPT DhcpOpt);
USHORT Build_DHCPOpt_81(char* FQDN, PDHCP_OPT DhcpOpt);
USHORT Build_DHCPOpt_61(PUCHAR MacAddr, PDHCP_OPT DhcpOpt);
USHORT Build_DHCPOpt(BYTE OptionType, BYTE OptionLength, PBYTE OptionValue, PDHCP_OPT pDhcpOpt);
bool IsIPv4AddrPlumbebOnAdapter(int IfIndex, char* IPv4);
bool IsMultihomed();
DWORD ListAllAdapters();
DWORD MyEcho(char* IpAddr);
LARGE_INTEGER UnixTimeToFileTime(time_t t);
DWORD WaitOnTimer(HANDLE hTimer, time_t time, const char* Msg);
bool CheckValidIpAddr(string IpAddr);
void CleanupAlternateIPv4OnInt(int IfIndex, char* IPv4);
DWORD GetAdapterMacByIndex(int IfIndex, BYTE(&MAC)[ETHER_ADDR_LEN]);
DWORD Alloc_DHCPOpts(PDHCP_OPT*& ppDhcpOpts, int iNbrOpt);

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
		DHCPRawLease(pDHCP_PACKET& pDhcpAck, pDHCP_PACKET& pDhcpRequest, int ClientId){ Set_DHCPLease(pDhcpAck, pDhcpRequest, ClientId);}
		/////////////////////
		/// Methods
		/////////////////////
		void print();
		//
		pDHCP_LEASE Get_DHCPLease() { return m_pDhcpLease; }

	private:
		/////////////////////
		/// attributes
		/////////////////////	
		pDHCP_LEASE m_pDhcpLease = NULL;
		char m_LocalAddrIp[INET_ADDRSTRLEN] = { 0 };
		char m_ServerAddrIp[INET_ADDRSTRLEN] = { 0 };
		/////////////////////
		/// Methods
		/////////////////////
		void Set_DHCPLease(pDHCP_PACKET& pDhcpAck, pDHCP_PACKET& pDhcpRequest, int ClientId);
	};

	//DHCPRawMessage
	class DHCPRawPacket
	{
	private:
		/////////////////////
		/// attributes
		/////////////////////	
		pDHCP_PACKET m_pDhcpPacket;
		//pDHCP_PACKET	m_pDHCPv4_HDR	= NULL;
		pIPv4_HDR m_pIPv4_HDR;
		pUDPv4_HDR m_pUDPv4_HDR;

		/////////////////////
		/// Methods
		/////////////////////
		// Create pIPV4 and UDPv4 hearder
		DWORD Set_DHCPMsg(BYTE dhcp_opcode, BYTE dhcp_flags, ULONG dhcp_gip, BYTE(&dhcp_chaddr)[ETHER_ADDR_LEN]);
	
	public:
		/////////////////////
		/// Constructor
		/////////////////////
		DHCPRawPacket()
		{
			//
		}
		DHCPRawPacket(BYTE(&dhcp_chaddr)[ETHER_ADDR_LEN], bool isRelayOn);
		~DHCPRawPacket();

		/////////////////////
		/// Methods
		/////////////////////
		void print();
		//
		pDHCP_PACKET get_pDhcpPacket(){ return m_pDhcpPacket;}
		pIPv4_HDR get_pIPv4hdr(){ return m_pIPv4_HDR;}
		pUDPv4_HDR get_pUDPv4hdr(){ return m_pUDPv4_HDR;}
		pDHCPv4_HDR get_pDhcpMsg() 
		{ 

			if (m_pDhcpPacket->m_pDhcpMsg != NULL)
				return m_pDhcpPacket->m_pDhcpMsg;
			else
				return NULL;
		}

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
			DHCPRawClient(int number, int ifindex, bool isRelayOn, string ClientPrefixName, vector<string> StrCustomOpt, vector<int> ParamReqList);
			//Sender DHCPRawClient Objects
			DHCPRawClient(int number, bool isReceiver, bool bIsRealyOn);
			//Relay  DHCPRawClient Objects
			DHCPRawClient(int number, int ifindex, bool isRelayOn, string ClientPrefixName, vector<string> StrCustomOpt, vector<int> ParamReqList, vector<string> RelayAddrs, vector<string> SrvAddrs);
			~DHCPRawClient();
			
			/////////////////////
			/// Methods
			/////////////////////
			void print();
			void EntryPoint_DHCPClient();
			int Get_DHCPClient_Number() { return m_ClientNumber; }

		private:
			/////////////////////
			/// attributes
			/////////////////////			
			HANDLE m_hTimer = NULL;

			BYTE m_MAC[ETHER_ADDR_LEN]{ 0,0,0,0,0,0 };
			int	m_IfIndex = 0;
			int	m_ClientNumber = 0;
			int	m_TransitionState = TransitionState::Init;
			int	m_NumberOfCustomOpts = 0;
			bool m_IsReceiver = false;
			bool m_IsOfferReceive = false;
			bool m_IsRelayMode = FALSE;
			
			vector<string> m_RelayAddrs;
			vector<string> m_SrvAddrs;

			vector<int> m_ParamReqList;
			vector<PDHCP_OPT> m_pCustomDhcpOpts;

			string m_ClientNamePrefix;
			DHCPRawPacket *m_DHCPRawPacket;

			DHCPRawLease m_DhcpRawLease;
			//pDHCP_PACKET is the struct enqueued to the hashtable... DHCP Sender/receiver will then consume it.
			pDHCP_PACKET m_pDhcpOutstandingRequest = NULL;
			pDHCP_PACKET m_pDhcpOffer	= NULL;
			pDHCP_PACKET m_pDhcpAck		= NULL;
			pDHCP_LEASE	 m_pDhcpLease	= NULL;
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
			DWORD Run_DHCPClient();
			DWORD Run_DHCPReceiver();
			DWORD Wait_DhcpClient_OnT1T2EndOfLease();
			//
			DWORD Send_Dhcp_Packet(pDHCP_PACKET DhcpPacket, pIPv4_HDR myIPv4Hdr, pUDPv4_HDR myUDPv4hdr);
			DWORD Set_DHCPRequest_CompletionEvent(int bucket, pDHCP_PACKET Reply);
			DWORD Set_Transition_State(int NewState);
			DWORD build_dhpc_request(pDHCP_PACKET DhcpPacket);
			DWORD add_dhcp_opts_to_request(pDHCP_PACKET DhcpPacket);

			bool AcceptOffer(pDHCP_PACKET m_pDhcpOffer);
			//
			DWORD ConvertStrOptToDhpOpt(vector<string> StrCustomOpt);
	};

}