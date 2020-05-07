#include "DHCPRaw.h"

#define DHCP_OPT_NBR_DISCVOVER 3

#define EthAddrEquals(x1,x2)	((x1))

DhcpMsgQ DHCPOutstandingMsgQ[DHCP_REPLY];
bool g_bRelayMode = false;

namespace DHCPRaw
{
	using namespace std;

/////////////////////////////
//DHCPRawMessage Class Functions
/////////////////////////////
DWORD InsertLock(int bucket, pDHCP_PACKET& m_pDhcpPacket)
{
	DEBUG_PRINT("--> InsertLock in Q=%d Qsize=%d Xid=%.8X\n",bucket, DHCPOutstandingMsgQ[bucket].size(), ntohl((m_pDhcpPacket->m_pDhcpMsg->dhcp_xid)));

	EnterCriticalSection(&g_CS[bucket]);
	DHCPOutstandingMsgQ[bucket].insert(m_pDhcpPacket);
	LeaveCriticalSection(&g_CS[bucket]);

	DEBUG_PRINT("<-- InsertLock in Q=%d Qsize=%d Xid=%.8X\n",bucket, DHCPOutstandingMsgQ[bucket].size(), ntohl((m_pDhcpPacket->m_pDhcpMsg->dhcp_xid)));

	return EXIT_SUCCESS;
}

DWORD RemoveLock(int bucket, pDHCP_PACKET& m_pDhcpPacket)
{
	DEBUG_PRINT("--> RemoveLock Q=%d Qsize=%d Xid=%.8X\n",bucket, DHCPOutstandingMsgQ[bucket].size(), ntohl((m_pDhcpPacket->m_pDhcpMsg->dhcp_xid)));

	EnterCriticalSection(&g_CS[bucket]);
	DHCPOutstandingMsgQ[bucket].erase(m_pDhcpPacket);
	LeaveCriticalSection(&g_CS[bucket]);

	DEBUG_PRINT("<-- RemoveLock Q=%d Qsize=%d Xid=%.8X\n",bucket, DHCPOutstandingMsgQ[bucket].size(), ntohl((m_pDhcpPacket->m_pDhcpMsg->dhcp_xid)));

	return EXIT_SUCCESS;
}

pDHCP_PACKET FindElement(int bucket, pDHCP_PACKET& m_pDhcpRequest)
{
	DEBUG_PRINT("--> FindElement in Q=%d Qsize=%d Xid=%.8X\n",bucket, DHCPOutstandingMsgQ[bucket].size(), ntohl(m_pDhcpRequest->m_pDhcpMsg->dhcp_xid));

	EnterCriticalSection(&g_CS[bucket]);
	DhcpMsgQ::const_iterator DhcpPacket = DHCPOutstandingMsgQ[bucket].find(m_pDhcpRequest);
	LeaveCriticalSection(&g_CS[bucket]);

	DEBUG_PRINT("<-- FindElement in Q=%d Qsize=%d Xid=%.8X\n",bucket, DHCPOutstandingMsgQ[bucket].size(), ntohl((ULONG)(*DhcpPacket)->m_pDhcpMsg->dhcp_xid));

	return (pDHCP_PACKET)*DhcpPacket;
}

pDHCP_PACKET ExtractElement(int bucket, pDHCP_PACKET& m_pDhcpPacket)
{
	DEBUG_PRINT("--> ExtractElement in Q=%dQsize=%d Xid=%.8X\n",bucket, DHCPOutstandingMsgQ[bucket].size(), ntohl(m_pDhcpPacket->m_pDhcpMsg->dhcp_xid));

	EnterCriticalSection(&g_CS[bucket]);
	DhcpMsgQ::node_type node = DHCPOutstandingMsgQ[bucket].extract(m_pDhcpPacket);
	LeaveCriticalSection(&g_CS[bucket]);

	pDHCP_PACKET DhcpPacket = node.value();

	DEBUG_PRINT("<-- ExtractElement in Q=%d Qsize=%d Xid=%.8X\n",bucket, DHCPOutstandingMsgQ[bucket].size(), ntohl(DhcpPacket->m_pDhcpMsg->dhcp_xid));

	return DhcpPacket;
}

/////////////////////////////
//DHCPRawMessage Class Functions
/////////////////////////////
DHCPRawMessage::DHCPRawMessage(BYTE(&dhcp_chaddr)[ETHER_ADDR_LEN])
{
	/* Init DHCP Message */
	BYTE dhcp_flags =  DHCP_UNICAST_FLAG << 7;

	SetDhcpMessage(DHCP_REQUEST, dhcp_flags, INADDR_ANY, dhcp_chaddr);
	//IPv4 and UDPv4 Headers
	USHORT UdpSrcPort = DHCP_UDP_CPORT;

	m_pIPv4_HDR = BuildIPv4Hdr(INADDR_ANY, INADDR_BROADCAST, 0, IPPROTO_UDP);
	m_pUDPv4_HDR = BuildUDPv4Hdr(UdpSrcPort, DHCP_UDP_SPORT, 0);
}

DHCPRawMessage::DHCPRawMessage(BYTE(&dhcp_chaddr)[ETHER_ADDR_LEN], bool IsRealyOn, char* RelayAddr,char* SrvAddr)
{
	/* Init DHCP Message */
	BYTE dhcp_flags = IsRealyOn == TRUE ? DHCP_BROADCAST_FLAG << 7 : DHCP_UNICAST_FLAG << 7;
	ULONG srcAddr = IsRealyOn == TRUE ? inet_addr(RelayAddr) : INADDR_ANY;
	ULONG dstAddr = IsRealyOn == TRUE ? inet_addr(SrvAddr) : INADDR_BROADCAST;

	SetDhcpMessage(DHCP_REQUEST, dhcp_flags, srcAddr, dhcp_chaddr);
	//IPv4 and UDPv4 Headers
	USHORT UdpSrcPort = IsRealyOn == TRUE ? DHCP_UDP_SPORT : DHCP_UDP_CPORT;

	m_pIPv4_HDR = BuildIPv4Hdr(srcAddr, dstAddr, 0, IPPROTO_UDP);
	m_pUDPv4_HDR = BuildUDPv4Hdr(UdpSrcPort, DHCP_UDP_SPORT, 0);
}

pIPv4_HDR DHCPRawMessage::get_IPv4_HDR()
{
	return m_pIPv4_HDR;
}

pUDPv4_HDR DHCPRawMessage::get_UDPv4_HDR()
{
	return m_pUDPv4_HDR;
}

pDHCPv4_HDR DHCPRawMessage::get_DhcpMsg()
{
	return m_pDhcpMsg;
}

DWORD DHCPRawMessage::SetDhcpMessage(BYTE dhcp_opcode, BYTE dhcp_flags, ULONG dhcp_gip, BYTE(&dhcp_chaddr)[ETHER_ADDR_LEN])
{
	m_pDhcpMsg = (pDHCPv4_HDR)malloc(sizeof(DHCPv4_HDR));

	//DHCPv4_HDR_size = (USHORT)(sizeof(DHCPv4_HDR));

	m_pDhcpMsg->dhcp_opcode = dhcp_opcode;
	m_pDhcpMsg->dhcp_htype = 0x1;
	m_pDhcpMsg->dhcp_hlen = 0x6;
	m_pDhcpMsg->dhcp_hopcount = 0;

	/* Sleep a bit to change TickCount to have random number for xID generation*/
	Sleep(100);
	m_pDhcpMsg->dhcp_xid = 0;
	for (int i = 0; i < 4; i++) {
		srand(GetTickCount());
		int msb = (rand() % 2) << 15;
		m_pDhcpMsg->dhcp_xid += (msb | rand());
	}

	m_pDhcpMsg->dhcp_secs = 0;
	//	DhcpMsg->dhcp_flags = g_bRelayMode == TRUE ? DHCP_BROADCAST_FLAG << 7 : DHCP_UNICAST_FLAG << 7;
	m_pDhcpMsg->dhcp_flags = dhcp_flags << 7;
	m_pDhcpMsg->dhcp_cip = 0;
	m_pDhcpMsg->dhcp_yip = 0;
	m_pDhcpMsg->dhcp_sip = 0;
	/* If RelayAgent mode set the IP to GIADDR*/
	//printf("g_bRelayMode=%d SrcIp=%s\n", g_bRelayMode, SrcIp);
	//pDhcpMsg->dhcp_gip = g_bRelayMode == TRUE ? inet_addr(dhcp_gip) : 0;
	m_pDhcpMsg->dhcp_gip = dhcp_gip;

	memset(m_pDhcpMsg->dhcp_chaddr, NULL, 16);
	memcpy(m_pDhcpMsg->dhcp_chaddr, dhcp_chaddr, ETHER_ADDR_LEN);
	memset(m_pDhcpMsg->dhcp_sname, NULL, sizeof(BYTE) * 64);
	memset(m_pDhcpMsg->dhcp_file, NULL, sizeof(BYTE) * 128);

	m_pDhcpMsg->dhcp_magic = htonl(DHCP_MAGIC);

	return EXIT_SUCCESS;
}

HANDLE DHCPRawMessage::Run()
{
	HANDLE handle = NULL;
	return handle;
}

void DHCPRawMessage::print()
{
	char dhcp_cip[INET_ADDRSTRLEN];
	char dhcp_yip[INET_ADDRSTRLEN];
	char dhcp_sip[INET_ADDRSTRLEN];
	char dhcp_gip[INET_ADDRSTRLEN];

	if (sizeof(m_pDhcpMsg) != NULL)
	{

		inet_ntop(AF_INET, &(m_pDhcpMsg->dhcp_cip), dhcp_cip, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(m_pDhcpMsg->dhcp_yip), dhcp_yip, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(m_pDhcpMsg->dhcp_sip), dhcp_sip, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(m_pDhcpMsg->dhcp_gip), dhcp_gip, INET_ADDRSTRLEN);

		printf("####################\n");
		printf("# DUMPING DHCP MSG #\n");
		printf("####################\n");
		printf("dhcp_opcode=%d\ndhcp_htype=%d\ndhcp_hlen=%d\ndhcp_hopcount=%d\ndhcp_xid=%.8X\ndhcp_secs=%d\ndhcp_flags=%.4X\n",
			m_pDhcpMsg->dhcp_opcode, m_pDhcpMsg->dhcp_htype, m_pDhcpMsg->dhcp_hlen, m_pDhcpMsg->dhcp_hopcount, \
			m_pDhcpMsg->dhcp_xid, m_pDhcpMsg->dhcp_secs, m_pDhcpMsg->dhcp_flags);

		printf("dhcp_cip=%s\ndhcp_yip=%s\ndhcp_sip=%s\ndhcp_gip=%s\ndhcp_chaddr=%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\ndhcp_sname=%s\ndhcp_file=%s\ndhcp_magic=%.8X\n", \
			dhcp_cip, dhcp_yip, dhcp_sip, dhcp_gip, m_pDhcpMsg->dhcp_chaddr[0], m_pDhcpMsg->dhcp_chaddr[1],
			m_pDhcpMsg->dhcp_chaddr[2], m_pDhcpMsg->dhcp_chaddr[3], m_pDhcpMsg->dhcp_chaddr[4], m_pDhcpMsg->dhcp_chaddr[5], \
			m_pDhcpMsg->dhcp_sname, m_pDhcpMsg->dhcp_file, m_pDhcpMsg->dhcp_magic
		);
		printf("####################\n");
	}
}



/////////////////////////////
//DHCPCLient Class Functions
/////////////////////////////

//DHCPRawClient regular mode (BROADCAST)
DHCPRawClient::DHCPRawClient(int number, int ifindex,char* ClientPrefixName)
{
	//Attributes
	//m_IsReceiver = isReceiver;
	//If not DHCP SenderReceiver
	m_ClientNumber = number;
	m_IfIndex = ifindex;
	m_ClientNamePrefix = (char*)malloc(strlen(ClientPrefixName)* sizeof(char));
	memcpy(m_ClientNamePrefix, ClientPrefixName, strlen(ClientPrefixName) * sizeof(char));

	// setMAc from adapter with ifIndex = m_IfIndex;
	if (setMAC() == EXIT_FAILURE) { cout << "Cannot get MAC address from ifIndex:" << m_IfIndex << endl; }
	//
	m_DhcpRawMsg = DHCPRawMessage(m_MAC);


}

//DHCPRawClient regular mode (RELAY)
DHCPRawClient::DHCPRawClient(int number, int ifindex, char* ClientPrefixName, bool isRelayOn, char* RelayAddr,char *SrvAddr)
{
	//Attributes
	//m_IsReceiver = isReceiver;
	//If not DHCP SenderReceiver
	m_ClientNumber = number;
	m_IfIndex = ifindex;
	m_ClientNamePrefix = (char*)malloc(strlen(ClientPrefixName) * sizeof(char));
	memcpy(m_ClientNamePrefix, ClientPrefixName, strlen(ClientPrefixName) * sizeof(char));

	// setMAc from adapter with ifIndex = m_IfIndex;
	if (setMAC() == EXIT_FAILURE) { cout << "Cannot get MAC address from ifIndex:" << m_IfIndex << endl; }
	//
	m_DhcpRawMsg = DHCPRawMessage(m_MAC,isRelayOn,RelayAddr,SrvAddr);
	m_gRelayMode = isRelayOn;
	m_RelayAddr = RelayAddr;
	m_SrvAddr = SrvAddr;

	//this->print();
}

//DHCPRawClient Receiver
DHCPRawClient::DHCPRawClient(int number, bool isReceiver, bool bIsRealyOn)
{
	//Attributes
	m_IsReceiver = isReceiver;
	m_gRelayMode = bIsRealyOn;
}

//Default object printer
void DHCPRawClient::print()
{
	//If not DHCP SenderReceiver
	if (!m_IsReceiver)
	{
		//print client number
		cout << "Client: " << m_ClientNumber << endl;
		//print ifIndex
		cout << "ifIndex: " << m_IfIndex << endl;
		//print MAC address
		for (int i = 0; i < ETHER_ADDR_LEN; i++)
		{
			printf("%.2x", m_MAC[i]);
			if (i != ETHER_ADDR_LEN - 1)
				cout << ":";
		}
		cout << endl;
		// Print DHCP thread kind
		cout << "IsReceiver: " << m_IsReceiver << endl;
		// Print DHCPMessage
		m_DhcpRawMsg.print();
	}
}

int DHCPRawClient::getClientNumber()
{
	return m_ClientNumber;
}

DWORD DHCPRawClient::setMAC()
{
	int ret = EXIT_FAILURE;

	ret = GetAdapterMacByIndex(m_IfIndex, m_MAC); // see utils.c
	if (ret == EXIT_SUCCESS)
	{	
		m_MAC[ETHER_ADDR_LEN - 1] = m_ClientNumber & 0xFF;
		m_MAC[ETHER_ADDR_LEN - 2] = (m_ClientNumber >> 8);
	}
	return ret;
}

DWORD DHCPRawClient::SetStateTransition(int NewState)
{
	
	DEBUG_PRINT("--> SetStateTransition from %d to %d\n", m_StateTransition, NewState);

	if (NewState >= StateTransition::Init && NewState <= StateTransition::Rebinding)
		m_StateTransition = NewState;
	else
		return EXIT_FAILURE;

	DEBUG_PRINT("<-- SetStateTransition\n");;

	return EXIT_SUCCESS;
}


/* DHCP Client Thread:
	* Wait DHCP Receiver to be readay
	* Sent DHCP Discover (pass it to relay by inserted it to the Queue if needed)
	* Consume any DHCP Offer and reply accordingly by a request
	* to the Q (do 3 restransmit)
*/
DWORD DHCPRawClient::DhcpClient()
{
	DEBUG_PRINT("--> DHCPRawClient::DhcpClient() CLient:%d\n", m_ClientNumber);

	/* First wait on that the DHCP receiver*/
	DWORD dwWaitResultOnSocketEvent;
	DWORD dwWaitOnCompletionRequest;
	
	time_t st_ltime = 0;
	time_t m_pDhcpRequest_ltime = 0;

	pDHCP_PACKET pDhcpReply = NULL;

	/* Wait the DHCP Receiver beoin*/
	dwWaitResultOnSocketEvent = WaitForSingleObject(
		g_hSocketWaitEvent, // event handle
		INFINITE);    // ind


	switch (dwWaitResultOnSocketEvent)
	{
			// Event object was signaled
		case WAIT_OBJECT_0:
			//
			// TODO: Read from the shared buffer
			//
			////printf("DhcpClient(): Listening socket has been successfully created\n");
			break;

			// An error occurred
		default:
			printf("DHCPRawClient::DhcpClient(): Wait error (%d)\n", GetLastError());
			return EXIT_FAILURE;
	}


	pDHCP_PACKET pDhcpAck = NULL;
	HANDLE hTimer = NULL;
	LARGE_INTEGER liDueTime;

	liDueTime.QuadPart = -600000000LL;

	// Create an unnamed waitable timer.
	hTimer = CreateWaitableTimer(NULL, TRUE, NULL);
	if (NULL == hTimer)
	{
		printf("CreateWaitableTimer failed (%d)\n", GetLastError());
		return 1;
	}

	//Event g_hSocketWaitEvent has been signaled
	printf("DHCPRawClient::DhcpClient() CLient:%d is starting\n", m_ClientNumber);

	do
	{
		switch (m_StateTransition)
		{
			case StateTransition::Init:
				build_dhpc_request();
				break;
			case StateTransition::Selecting:
				build_dhpc_request();
				//Transit to Requesting
				SetStateTransition(m_StateTransition + 1);
				break;
			case StateTransition::Bound:
				//CreateLease
				m_DhcpRawLease = DHCPRawLease(m_pDhcpAck, m_ClientNumber);
				//m_pDhcpLease = m_DhcpLease.GetLease();
				Sleep(5 * m_ClientNumber);
				m_DhcpRawLease.print();
				//Wait T1 to Expire
				if (!SetWaitableTimer(hTimer, &liDueTime, 0, NULL, NULL, 0))
				{
					printf("SetWaitableTimer failed (%d)\n", GetLastError());
					return 2;
				}

				printf("Waiting for T1 expired...\n");

				// Wait for the timer.
				if (WaitForSingleObject(hTimer, INFINITE) != WAIT_OBJECT_0)
					printf("WaitForSingleObject failed (%d)\n", GetLastError());
				else printf("T1 is expired.\n");

				build_dhpc_request();
				SetStateTransition(m_StateTransition + 1);

				break;
			case StateTransition::Renewing:
				//Wait T2 to Expire
				if (!SetWaitableTimer(hTimer, &liDueTime, 0, NULL, NULL, 0))
				{
					printf("SetWaitableTimer failed (%d)\n", GetLastError());
					return 2;
				}

				printf("Waiting for T2 expired...\n");

				// Wait for the timer.
				if (WaitForSingleObject(hTimer, INFINITE) != WAIT_OBJECT_0)
					printf("WaitForSingleObject failed (%d)\n", GetLastError());
				else printf("T2 is expired.\n");

				build_dhpc_request();
				SetStateTransition(m_StateTransition + 1);

				break;
		}

		this->m_pDhcpRequest->hCompletionEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		if (this->m_pDhcpRequest->hCompletionEvent == NULL)
		{
			printf("DhcpPacket hCompletionEvent creation failed (%d)\n", GetLastError());
			return EXIT_FAILURE;
		}

		//Send this->m_pDhcpRequest
		InsertLock(DHCP_REQUEST - 1, this->m_pDhcpRequest);
		SendDhcpRequest();

		dwWaitOnCompletionRequest = WaitForSingleObject(
			this->m_pDhcpRequest->hCompletionEvent, // event handle
			DHCP_RETRANSMIT_TIMEOUT);    // 

		//Replace by a Wait on a semaphore Obj or a completion event set by Receiver (better :))
		switch (dwWaitOnCompletionRequest)
		{
			// Event object was signaled
			case WAIT_OBJECT_0:
				//
				// TODO: Read from the shared buffer
				//
				pDhcpReply = ExtractElement(DHCP_REPLY-1, this->m_pDhcpRequest);

				DEBUG_PRINT("DHCPRawClient::DhcpClient()  DCHP Reply received: MsgType=%d\n", pDhcpReply->m_ppDhcpOpt[0]->OptionValue[0]);
				switch ((int)pDhcpReply->m_ppDhcpOpt[0]->OptionValue[0])
				{
					case DHCP_MSGOFFER:
						SetStateTransition(m_StateTransition + 1);
						m_pDhcpOffer = pDhcpReply;
						break;

					case DHCP_MSGACK:
						if ( m_StateTransition != StateTransition::Renewing)
							SetStateTransition(StateTransition::Bound);
						else
							SetStateTransition(StateTransition::Rebinding);			

						m_pDhcpAck = pDhcpReply;
						break;

					case DHCP_MSGNACK:
						SetStateTransition(StateTransition::Init);
						break;
				}

				ResetEvent(this->m_pDhcpRequest->hCompletionEvent);

				break;
			case WAIT_TIMEOUT:
				//
				// TODO: Read from the shared buffer
				//
				printf("DHCPRawClient::DhcpClient(): CLient:%d DHCP Reply not received... Will retry...\n", m_ClientNumber);
				break;
				// An error occurred
			default:
				printf("DHCPRawClient::DhcpClient(): Wait error (%d)\n", GetLastError());
				return EXIT_FAILURE;
		}
	}while (true);//LeaseNotGranter or Retry > 3 


	DEBUG_PRINT("--> DHCPRawClient::DhcpClient() CLient:%d\n", m_ClientNumber);

	//free(m_pDhcpRequest);

	return EXIT_SUCCESS;
}

DWORD DHCPRawClient::build_dhpc_request()
{
	printf("--> DHCPRawClient::build_dhpc_request CLient:%d\n", m_ClientNumber);
	
	char* pchDomainName = NULL;
	char* pcClientFQDN = (char*)malloc(sizeof(char) * strlen((const char*)m_ClientNamePrefix) + 255);
	USHORT iNbrOpt = 0;
	USHORT iDhcpOptSize = 0;
	USHORT iDhcpOpt = 0;
	int DhcpMsgType = DHCP_MSGREQUEST;
	BYTE rgb_ParameterRequestList[5] = { DHCP_SUBNETMASK, DHCP_BROADCASTADDR, DHCP_ROUTER, DHCP_DOMAINNAME, DHCP_DNS };

	pDHCP_PACKET m_pDhcpReply = NULL;
	pDHCP_PACKET DhcpPacket = (pDHCP_PACKET)malloc(sizeof(DHCP_PACKET));
	pDHCP_PACKET m_pDhcpPreviousRequest = this->m_pDhcpRequest;

	switch (m_StateTransition)
	{
		case StateTransition::Init:
			iNbrOpt = DHCP_OPT_NBR_DISCVOVER;
			DhcpMsgType = DHCP_MSGDISCOVER;
			DhcpPacket->m_pDhcpMsg = m_DhcpRawMsg.get_DhcpMsg();
			break;
		case StateTransition::Selecting:
			m_pDhcpReply = this->m_pDhcpOffer;
			iNbrOpt = m_pDhcpPreviousRequest->m_iNbrOpt;
			if (m_pDhcpReply->m_pDhcpMsg->dhcp_sip != 0)
				iNbrOpt++;

			iNbrOpt += 2;
			break;
		default:
			m_pDhcpReply = this->m_pDhcpAck;
			iNbrOpt = m_pDhcpPreviousRequest->m_iNbrOpt;
			if (m_pDhcpReply->m_pDhcpMsg->dhcp_sip != 0)
				iNbrOpt++;
			iNbrOpt += 2;
			break;
	}
	
	//Something wrong here....
	if (DhcpPacket == NULL)
		return EXIT_FAILURE;

	//Allocate space  DhcpOptions

	DhcpPacket->m_ppDhcpOpt = (PDHCP_OPT*)malloc(sizeof(PDHCP_OPT) * iNbrOpt);
	for (int i = 0; i < iNbrOpt; i++)
		DhcpPacket->m_ppDhcpOpt[i] = (PDHCP_OPT)malloc(sizeof(DHCP_OPT));

	if (m_StateTransition == StateTransition::Init)
	{
		iDhcpOptSize += build_option53(DHCP_MSGDISCOVER, DhcpPacket->m_ppDhcpOpt[iDhcpOpt]);
		iDhcpOpt++;
	
		iDhcpOptSize += build_option50_54(DHCP_REQUESTEDIP, DhcpPacket->m_pDhcpMsg->dhcp_cip,DhcpPacket->m_ppDhcpOpt[iDhcpOpt]);
		iDhcpOpt++;
	
		iDhcpOptSize += build_option_55(rgb_ParameterRequestList, DhcpPacket->m_ppDhcpOpt[iDhcpOpt]);
		iDhcpOpt++;
	}
	else
	{
		//Something wrong here.... 
		if (m_pDhcpReply == NULL || m_pDhcpPreviousRequest == NULL)
			return EXIT_FAILURE;

		DhcpPacket->m_pDhcpMsg = (pDHCPv4_HDR)malloc(sizeof(DHCPv4_HDR));
		memcpy(DhcpPacket->m_pDhcpMsg, m_pDhcpReply->m_pDhcpMsg, sizeof(DHCPv4_HDR));

		DhcpPacket->m_pDhcpMsg->dhcp_opcode = DHCP_REQUEST;
		DhcpPacket->m_pDhcpMsg->dhcp_yip = 0;

		for (int i = 0; i < m_pDhcpReply->m_iNbrOpt; i++)
		{
			//Get the domain name from the DHCP Reply
			if (m_pDhcpReply->m_ppDhcpOpt[i]->OptionType == DHCP_DOMAINNAME)
			{
				pchDomainName = (char*)malloc(strlen((const char*)m_pDhcpReply->m_ppDhcpOpt[i]->OptionValue) * sizeof(BYTE));
				pchDomainName = (char*)m_pDhcpReply->m_ppDhcpOpt[i]->OptionValue;
			}
		}

		for (int i = 0; i < m_pDhcpPreviousRequest->m_iNbrOpt; i++)
		{
			DhcpPacket->m_ppDhcpOpt[i] = m_pDhcpPreviousRequest->m_ppDhcpOpt[i];
			iDhcpOptSize += m_pDhcpPreviousRequest->m_ppDhcpOpt[i]->OptionLength + 2;

			switch (m_pDhcpPreviousRequest->m_ppDhcpOpt[i]->OptionType)
			{
				case DHCP_MESSAGETYPE:
					build_option53(DhcpMsgType, DhcpPacket->m_ppDhcpOpt[i]);
					break;
				case DHCP_REQUESTEDIP: //Getting the proposed IP and add it option 50 DHCP_REQUESTEDIP... That's what we want to do !
					build_option50_54(DHCP_REQUESTEDIP, htonl(m_pDhcpReply->m_pDhcpMsg->dhcp_yip), DhcpPacket->m_ppDhcpOpt[i]);
					break;
			}
			iDhcpOpt++;
		}

		iDhcpOptSize += build_option_61(DhcpPacket->m_pDhcpMsg->dhcp_chaddr, DhcpPacket->m_ppDhcpOpt[iDhcpOpt]);
		iDhcpOpt++;

		sprintf(pcClientFQDN, "%s%d.%s", m_ClientNamePrefix, m_pDhcpReply->m_pDhcpMsg->dhcp_chaddr[5], pchDomainName);

		iDhcpOptSize += build_option_81(pcClientFQDN, DhcpPacket->m_ppDhcpOpt[iDhcpOpt]);
		iDhcpOpt++;

		// adding srv identity
		if (m_pDhcpReply->m_pDhcpMsg->dhcp_sip > 0)
		{
			iDhcpOptSize += build_option50_54(DHCP_SERVIDENT, htonl(m_pDhcpReply->m_pDhcpMsg->dhcp_sip), DhcpPacket->m_ppDhcpOpt[iDhcpOpt]);
			iDhcpOpt++;
		}
	}
		
	DhcpPacket->m_pDhcpMsg->dhcp_sip = 0;
	DhcpPacket->m_iSizeOpt = iDhcpOptSize;
	DhcpPacket->m_iNbrOpt = iNbrOpt;
	DhcpPacket->m_ltime = 0;
	DhcpPacket->m_iRetry = 0;

	// Assigning the DHCPpacket to the DHCPRawclient Object
	this->m_pDhcpRequest = DhcpPacket;
	
	DhcpPacket = NULL;

	printf("<-- DHCPRawClient::build_dhpc_request CLient:%d\n", m_ClientNumber);

	return EXIT_SUCCESS;
}



DWORD DHCPRawClient::SetDHCPRequestCompletionEvent(int bucket, pDHCP_PACKET pDhcpReply)
{
	DEBUG_PRINT("--> DHCPRawClient::SetDHCPRequestCompletionEvent CLient:%d\n", m_ClientNumber);

	pDHCP_PACKET pDhcpRequest = ExtractElement(bucket, pDhcpReply);
	if (pDhcpRequest != NULL)
	{
		DEBUG_PRINT("--> DHCPRawClient::SetDHCPRequestCompletionEvent RequestXID:=%.8X ReplyXID=%.8X\n", 
			ntohl((pDhcpRequest->m_pDhcpMsg->dhcp_xid)), ntohl((pDhcpReply->m_pDhcpMsg->dhcp_xid)));

		if ((pDhcpRequest->m_pDhcpMsg->dhcp_xid == pDhcpReply->m_pDhcpMsg->dhcp_xid))
		{
			//Sets the event in order to let the sending thread to start his work
			if (!SetEvent(pDhcpRequest->hCompletionEvent))
			{
				printf("DHCPRawClient::SetCompletionEvent failed (%d)\n", GetLastError());
			}
			return EXIT_SUCCESS;
		}
	}
	DEBUG_PRINT("<-- DHCPRawClient::SetDHCPRequestCompletionEvent CLient:%d\n", m_ClientNumber);

	return EXIT_FAILURE;
}

//WorkerThread routine
HANDLE DHCPRawClient::Run()
{
	return CreateThread(NULL,
		0,
		ThreadEntryPoint,
		this,
		0,
		NULL);
}

/* DHCP Client Thread:
	* Wait DHCP Receiver to be readay
	* Sent DHCP Discover (pass it to relay by inserted it to the Queue if needed)
	* Consume any DHCP Offer and reply accordingly by a request
	* to the Q (do 3 restransmit)
*/
DWORD DHCPRawClient::DhcpReceiver()
{
	DEBUG_PRINT("--> DHCPRawClient::Receiver()\n");

	int iResult = 0;
	int i = 0;
	int optval = 1;
	int SenderAddrSize = DHCP_MAX_PACKET_SIZE;
	int recvbytes = 0;
	int request = 0;

	//	DWORD dwWaitResult;
	BYTE DhcpMsgType = 0;
	USHORT DhcpOptSize = 0;

	SOCKET RcvSocket;
	SOCKADDR_STORAGE rcvfrom;
	WSADATA wsaData = { 0 };
	pDHCP_PACKET  DhcpReply = NULL;

	char* RecvBuff = (char*)(malloc(sizeof(char) * DHCP_MAX_PACKET_SIZE));;

	/* Initialize Winsock DLL usage */
	iResult = WSAStartup(MAKEWORD(2, 0), &wsaData);
	if (iResult != 0)
	{
		printf("DHCPRawClient::Receive(): Error WSAStartup() call failed: %d\n", WSAGetLastError());
		goto cleanup;
	}

	((SOCKADDR_IN*)&rcvfrom)->sin_family = AF_INET;
	/* Set DHCP Relay port 67 if relay mode enable otherwise 68 */
	((SOCKADDR_IN*)&rcvfrom)->sin_port = m_gRelayMode == TRUE ? htons(DHCP_UDP_SPORT) : htons(DHCP_UDP_CPORT);
	((SOCKADDR_IN*)&rcvfrom)->sin_addr.s_addr = inet_addr("0.0.0.0");

	//REceiving packet
	RcvSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (RcvSocket == INVALID_SOCKET) 
	{
		printf("DHCPRawClient::Receive(): Error socket() call failed: %d\n", WSAGetLastError());
		goto cleanup;
	}

	if (m_gRelayMode == FALSE)
	{
		if (setsockopt(RcvSocket, SOL_SOCKET, SO_BROADCAST, (char*)&optval, sizeof(optval)) == SOCKET_ERROR) {
			printf("DHCPRawClient::Receive(): Error setsockopt() call failed : %d\n", WSAGetLastError());
			goto cleanup;
		}
	}
	else
	{
		if (setsockopt(RcvSocket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char*)&optval, sizeof(optval)) == SOCKET_ERROR) {
			printf("DHCPRawClient::Receive(): Error setsockopt() call failed : %d\n", WSAGetLastError());
			goto cleanup;
		}
	}

	//----------------------
	// Bind the socket.
	iResult = bind(RcvSocket, (SOCKADDR*)&rcvfrom, sizeof(rcvfrom));
	if (iResult == SOCKET_ERROR)
	{
		printf("DHCPRawClient::Receive(): Error bind() call failed : %d\n", WSAGetLastError());
		goto cleanup;
	}

	//Sets the event in order to let the sending thread to start his work
	if (!SetEvent(g_hSocketWaitEvent))
	{
		printf("DHCPRawClient::Receive(): SetEvent failed (%d)\n", GetLastError());
		goto cleanup;
	}
	
	//while (!bEndOfProgram)
	for (;;) 
	{
		recvbytes = recvfrom(RcvSocket, RecvBuff, DHCP_MAX_PACKET_SIZE, 0, (SOCKADDR*)&rcvfrom, &SenderAddrSize);

		if (recvbytes == SOCKET_ERROR)
			goto cleanup;

		DhcpReply = (pDHCP_PACKET)malloc(sizeof(DHCP_PACKET));
		DhcpReply->m_pDhcpMsg = (pDHCPv4_HDR)malloc(sizeof(DHCPv4_HDR));
		memcpy(DhcpReply->m_pDhcpMsg, RecvBuff, sizeof(DHCPv4_HDR));;

		if (recvbytes >= DHCP_MIN_PACKET_SIZE)
		{
			DEBUG_PRINT("DHCPRawClient::Receive(): DhcpMsg Received Bytes=%d\n", recvbytes);

			USHORT cpt = DHCPv4_H;
			USHORT nbrOpt = 0;
			while (cpt < recvbytes - 1)
			{
				cpt += (2 + RecvBuff[cpt + 1]);
				nbrOpt++;
			}
			DhcpReply->m_iSizeOpt = cpt - DHCPv4_H;
			DhcpReply->m_ppDhcpOpt = (PDHCP_OPT*)malloc(sizeof(PDHCP_OPT) * nbrOpt);

			cpt = DHCPv4_H;
			for (int i = 0; i < nbrOpt; i++)
			{
				DhcpReply->m_ppDhcpOpt[i] =	(PDHCP_OPT)malloc(sizeof(DHCP_OPT));
				DhcpReply->m_ppDhcpOpt[i]->OptionType = RecvBuff[cpt];
				DhcpReply->m_ppDhcpOpt[i]->OptionLength = RecvBuff[cpt + 1];
				DhcpReply->m_ppDhcpOpt[i]->OptionValue=(PBYTE)malloc((sizeof(BYTE)*DhcpReply->m_ppDhcpOpt[i]->OptionLength));
				for (int j = 0; j < DhcpReply->m_ppDhcpOpt[i]->OptionLength; j++)
					DhcpReply->m_ppDhcpOpt[i]->OptionValue[j] = RecvBuff[cpt + 2 + j];

				cpt += (2 + RecvBuff[cpt + 1]);
			}
			DhcpReply->m_iNbrOpt = nbrOpt;
			DhcpMsgType = (BYTE)DhcpReply->m_ppDhcpOpt[0]->OptionValue[0];

			//DhcpReply->m_pNext = NULL;

			//Timestamp the message before inserting it
			time(&(DhcpReply->m_ltime));

			//Insert Reply and signal compleation event
			InsertLock(DHCP_REPLY-1, DhcpReply);
			SetDHCPRequestCompletionEvent(DHCP_REQUEST-1, DhcpReply);
		}
		else
		{
			DhcpReply->m_iSizeOpt = 0;
			DhcpReply->m_iNbrOpt = 0;
		}


		iResult = WSAGetLastError(); // iResult turns 10057
										//Which means the socket isnt connected

		ZeroMemory(RecvBuff, sizeof(char)*DHCP_MAX_PACKET_SIZE);;
	}

	if (closesocket(RcvSocket) == SOCKET_ERROR) 
	{
		printf("DHCPRawClient::Receive(): Error closesocket() call failed : %d\n", WSAGetLastError());
		goto cleanup;
	}

	return EXIT_SUCCESS;

cleanup:
	closesocket(RcvSocket);
	WSACleanup();
	DEBUG_PRINT("<-- DHCPRawClient::Receive()\n");

	return EXIT_FAILURE;
}

DWORD DHCPRawClient::SendDhcpRequest()
{
	DEBUG_PRINT("--> SendDhcpRequest()\n");

	SOCKET sock;
	SOCKADDR_STORAGE src_sockaddr, dst_sockaddr;
	WSADATA wsaData = { 0 };
	
	pDHCP_PACKET DhcpPacket = this->m_pDhcpRequest;

	int iResult = 0, optval;
	pIPv4_HDR myIPv4Hdr = NULL;
	pUDPv4_HDR myUDPv4hdr = NULL;
	USHORT padding = 0;
	USHORT DHCPv4_HDR_len = sizeof(DHCPv4_HDR);
	USHORT dhcp_opt_len = DhcpPacket->m_iSizeOpt > 0 ? DhcpPacket->m_iSizeOpt + 2 : 1; //DHCP_END OPTION
	USHORT dhcp_msg_len = DHCPv4_HDR_len + dhcp_opt_len;
	USHORT udp_len = sizeof(UDPv4_HDR) + dhcp_msg_len;

	if (dhcp_msg_len >= DHCP_MIN_PACKET_SIZE)
		padding = 0;
	else
		padding = DHCP_MIN_PACKET_SIZE - dhcp_msg_len;

	USHORT ip_len = sizeof(IPv4_HDR) + udp_len + padding;
	char* buf = (char*)malloc(sizeof(char) * ip_len);

	//DEBUG_PRINT("SendDhcpRequest() g_bRelayMode=%d\n", g_bRelayMode);

	myIPv4Hdr = m_DhcpRawMsg.get_IPv4_HDR();
	myUDPv4hdr = m_DhcpRawMsg.get_UDPv4_HDR();

	myIPv4Hdr->ip_totallength = htons(ip_len);
	myUDPv4hdr->udp_length = htons(udp_len);

	memcpy(buf, myIPv4Hdr, sizeof(IPv4_HDR));
	memcpy(buf + sizeof(IPv4_HDR), myUDPv4hdr, sizeof(UDPv4_HDR));
	memcpy(buf + sizeof(IPv4_HDR) + sizeof(UDPv4_HDR), DhcpPacket->m_pDhcpMsg, DHCPv4_HDR_len);

	DEBUG_PRINT("SendDhcpRequest(): SEND PACKET ON WIRE SrcIp:%.4X:%d DStIp:%.4X:%d\n", myIPv4Hdr->ip_srcaddr,
		myUDPv4hdr->src_port, myIPv4Hdr->ip_destaddr, myUDPv4hdr->dst_port );

	if (dhcp_opt_len > 0 && DhcpPacket->m_iNbrOpt > 0)
	{
		char* OptBuf = NULL;
		OptBuf = (char*)malloc(sizeof(char) * dhcp_opt_len);
		USHORT offset = 0;
		//change DHCP_OPT to PDHCP_OPT 
		for (int i = 0; i < DhcpPacket->m_iNbrOpt; i++)
		{
			memcpy(OptBuf + offset, DhcpPacket->m_ppDhcpOpt[i], 1);
			memcpy(OptBuf + offset + 1, &DhcpPacket->m_ppDhcpOpt[i]->OptionLength, 1);
			memcpy(OptBuf + offset + 2, DhcpPacket->m_ppDhcpOpt[i]->OptionValue, DhcpPacket->m_ppDhcpOpt[i]->OptionLength);
			offset += DhcpPacket->m_ppDhcpOpt[i]->OptionLength + 2;
		}
		memset(OptBuf + offset, DHCP_END, sizeof(BYTE));
		memcpy(buf + sizeof(IPv4_HDR) + sizeof(UDPv4_HDR) + DHCPv4_HDR_len, OptBuf, dhcp_opt_len);
	}

	if (padding != 0)
		memset(buf + ip_len + 1 - padding, NULL, padding);

	iResult = WSAStartup(MAKEWORD(2, 0), &wsaData);

	if (iResult != 0) {
		printf("SendDhcpRequest() : WSAStartup call failed with error %d\n", WSAGetLastError());
		goto cleanup;
	}

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock == INVALID_SOCKET) 
	{
		printf("SendDhcpRequest() : socket call failed with error %d\n", WSAGetLastError());
		goto cleanup;
	}
	// Set the header include option
	optval = 1;
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char*)&optval, sizeof(optval)) == SOCKET_ERROR) 
	{
		printf("SendDhcpRequest() : setsockopt call failed with error %d\n", WSAGetLastError());
		goto cleanup;
	}

	if (myIPv4Hdr->ip_destaddr == INADDR_BROADCAST ) 
	{
		if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char*)&optval, sizeof(optval)) == SOCKET_ERROR) 
		{
			printf("SendDhcpRequest() : setsockopt call failed with error %d\n", WSAGetLastError());
			goto cleanup;
		}
	}
	// Send the data
	((SOCKADDR_IN*)&src_sockaddr)->sin_family = ((SOCKADDR_IN*)&dst_sockaddr)->sin_family = AF_INET;
	((SOCKADDR_IN*)&src_sockaddr)->sin_port = myUDPv4hdr->src_port;
	((SOCKADDR_IN*)&src_sockaddr)->sin_addr.s_addr = myIPv4Hdr->ip_srcaddr;

	// Send the data
	((SOCKADDR_IN*)&dst_sockaddr)->sin_port = myUDPv4hdr->dst_port;
	((SOCKADDR_IN*)&dst_sockaddr)->sin_addr.s_addr = myIPv4Hdr->ip_destaddr;

	//Timestamp the message before sending it
	time(&(DhcpPacket->m_ltime));

	if (sendto(sock, buf, ip_len, 0, (SOCKADDR*)&dst_sockaddr, sizeof(dst_sockaddr)) == SOCKET_ERROR) 
	{
		printf("SendDhcpRequest() : ERROR sendto() call from to %s:%d to %s:%d failed %d\n",
			myIPv4Hdr->ip_srcaddr, myUDPv4hdr->src_port, myIPv4Hdr->ip_destaddr, myUDPv4hdr->dst_port, WSAGetLastError());
	}

cleanup:
	DhcpPacket->m_iRetry++;

	closesocket(sock);
	WSACleanup();

	DEBUG_PRINT("<-- SendDhcpRequest()\n");

	return iResult;
}

/////////////////////////////
//DHCPRawLease Class Functions
/////////////////////////////

DHCPRawLease::DHCPRawLease(pDHCP_PACKET pDhcpAck, int ClientId)
{
	CreateLease(pDhcpAck, ClientId);
}

void DHCPRawLease::CreateLease(pDHCP_PACKET pDhcpAck, int ClientId)
{
	DEBUG_PRINT("--> DHCPRawLease::DhcpClient() CLient:%d\n", ClientId);
	

	m_pDhcpLease = (pDHCP_LEASE)malloc(sizeof(DHCP_LEASE));
	m_pDhcpLease->m_iClientID = ClientId;
	m_pDhcpLease->m_pDhcpPacketAck = pDhcpAck;
	m_pDhcpLease->m_T1 = 0;
	m_pDhcpLease->m_T2 = 0;

	ULONG seconds = 0;
	ULONG t1 = 0;
	ULONG t2 = 0;

	//Getting IP address
	inet_ntop(AF_INET, &(m_pDhcpLease->m_pDhcpPacketAck->m_pDhcpMsg->dhcp_yip), m_LocalAddrIp, INET_ADDRSTRLEN);


	//Compute T1 & T2
	for (int i = 0; i < m_pDhcpLease->m_pDhcpPacketAck->m_iNbrOpt; i++)
	{
		if (m_pDhcpLease->m_pDhcpPacketAck->m_ppDhcpOpt[i]->OptionType == DHCP_LEASETIME)
		{
			for(int j = 0; j < m_pDhcpLease->m_pDhcpPacketAck->m_ppDhcpOpt[i]->OptionLength; j++)
				seconds = (seconds * 0x100) + m_pDhcpLease->m_pDhcpPacketAck->m_ppDhcpOpt[i]->OptionValue[j];
			
			m_pDhcpLease->m_T2 = m_pDhcpLease->m_pDhcpPacketAck->m_ltime;
			m_pDhcpLease->m_T1 = m_pDhcpLease->m_pDhcpPacketAck->m_ltime;
			
			t1 = seconds / 2;
			m_pDhcpLease->m_T1 += t1;

			t2 = seconds*1000/875;
			m_pDhcpLease->m_T2 += t2;
		}

		if (m_pDhcpLease->m_pDhcpPacketAck->m_ppDhcpOpt[i]->OptionType == DHCP_SERVIDENT)
		{
			inet_ntop(AF_INET, &(m_pDhcpLease->m_pDhcpPacketAck->m_ppDhcpOpt[i]->OptionValue[0]), m_ServerAddrIp, INET_ADDRSTRLEN);
		}
	}

	DEBUG_PRINT("<-- DHCPRawLease::DhcpClient() CLient:%d\n", ClientId);
}

void DHCPRawLease::DeleteLease()
{

}

pDHCP_LEASE DHCPRawLease::GetLease()
{
	return m_pDhcpLease;
}

void DHCPRawLease::print()
{
	char dhcp_yip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(m_pDhcpLease->m_pDhcpPacketAck->m_pDhcpMsg->dhcp_yip), dhcp_yip, INET_ADDRSTRLEN);


	printf("LeaseGranted:\n");
	printf("\tClientID:%d\n\tMyIP:%s\n\tServerIP:%s\n", m_pDhcpLease->m_iClientID, m_LocalAddrIp,m_ServerAddrIp);
	char* t0 = ctime(&m_pDhcpLease->m_pDhcpPacketAck->m_ltime);
	printf("\tLeaseObtened:%s", t0);
	char* t1 = ctime(&m_pDhcpLease->m_T1);
	printf("\tT1:%s", t1);
	char* t2 = ctime(&m_pDhcpLease->m_T2);
	printf("\tT2:%s", t2);
}

}