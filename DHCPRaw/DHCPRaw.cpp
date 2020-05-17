#include "DHCPRaw.h"

#define DHCP_OPT_NBR_DISCVOVER 3

DhcpMsgQ DHCPOutstandingMsgQ[DHCP_REPLY];
bool g_bRelayMode = false;


namespace DHCPRaw
{
	using namespace std;

	/////////////////////////////
	//Qeue routine => The queue is just used let the DHCP Receiver thread calling DHCP request completion event
	/////////////////////////////
	DWORD InsertLock(int bucket, pDHCP_PACKET& pDhcpPacket)
	{
		DEBUG_PRINT("-->InsertLock in Q=%d Qsize=%d Xid=%.8X\n", bucket, DHCPOutstandingMsgQ[bucket].size(), ntohl((pDhcpPacket->m_pDhcpMsg->dhcp_xid)));

		EnterCriticalSection(&g_CS[bucket]);
		DHCPOutstandingMsgQ[bucket].insert(pDhcpPacket);
		LeaveCriticalSection(&g_CS[bucket]);

		DEBUG_PRINT("<--InsertLock in Q=%d Qsize=%d Xid=%.8X\n", bucket, DHCPOutstandingMsgQ[bucket].size(), ntohl((pDhcpPacket->m_pDhcpMsg->dhcp_xid)));

		return EXIT_SUCCESS;
	}

	DWORD RemoveLock(int bucket, pDHCP_PACKET& pDhcpPacket)
	{
		DEBUG_PRINT("-->RemoveLock Q=%d Qsize=%d Xid=%.8X\n", bucket, DHCPOutstandingMsgQ[bucket].size(), ntohl((pDhcpPacket->m_pDhcpMsg->dhcp_xid)));

		EnterCriticalSection(&g_CS[bucket]);
		DHCPOutstandingMsgQ[bucket].erase(pDhcpPacket);
		LeaveCriticalSection(&g_CS[bucket]);

		DEBUG_PRINT("<--RemoveLock Q=%d Qsize=%d Xid=%.8X\n", bucket, DHCPOutstandingMsgQ[bucket].size(), ntohl((pDhcpPacket->m_pDhcpMsg->dhcp_xid)));

		return EXIT_SUCCESS;
	}

	pDHCP_PACKET FindElement(int bucket, pDHCP_PACKET& pDhcpPacket)
	{
		DEBUG_PRINT("-->FindElement in Q=%d Qsize=%d Xid=%.8X\n", bucket, DHCPOutstandingMsgQ[bucket].size(), ntohl(pDhcpPacket->m_pDhcpMsg->dhcp_xid));

		EnterCriticalSection(&g_CS[bucket]);
		DhcpMsgQ::const_iterator DhcpPacket = DHCPOutstandingMsgQ[bucket].find(pDhcpPacket);
		LeaveCriticalSection(&g_CS[bucket]);

		//DEBUG_PRINT("<--FindElement in Q=%d Qsize=%d Xid=%.8X\n",bucket,DHCPOutstandingMsgQ[bucket].size(),ntohl(DhcpPacket->m_pDhcpMsg->dhcp_xid));

		return (pDHCP_PACKET)*DhcpPacket;
	}

	pDHCP_PACKET ExtractElement(int bucket, pDHCP_PACKET& pDhcpPacket)
	{
		DEBUG_PRINT("-->ExtractElement in Q=%d Qsize=%d Xid=%.8X\n", bucket, DHCPOutstandingMsgQ[bucket].size(), ntohl(pDhcpPacket->m_pDhcpMsg->dhcp_xid));

		EnterCriticalSection(&g_CS[bucket]);
		DhcpMsgQ::node_type node = DHCPOutstandingMsgQ[bucket].extract(pDhcpPacket);
		pDHCP_PACKET DhcpPacket = node.value();
		LeaveCriticalSection(&g_CS[bucket]);

		DEBUG_PRINT("<--ExtractElement in Q=%d Qsize=%d Xid=%.8X\n", bucket, DHCPOutstandingMsgQ[bucket].size(), ntohl(DhcpPacket->m_pDhcpMsg->dhcp_xid));

		return DhcpPacket;
	}

	//allocate a DCHP Packet
	DWORD NewDhcpPacket(pDHCP_PACKET& pDhcpPacket)
	{
		DEBUG_PRINT("-->NewDhcpPacket \n");

		pDhcpPacket = (pDHCP_PACKET)malloc(sizeof(DHCP_PACKET));
		pDhcpPacket->m_pDhcpMsg = (pDHCPv4_HDR)malloc(sizeof(DHCPv4_HDR));
		pDhcpPacket->m_ppDhcpOpt = NULL;
		pDhcpPacket->hCompletionEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		if (pDhcpPacket->hCompletionEvent == NULL)
		{
			printf("NewDhcpPacket: DhcpPacket hCompletionEvent creation failed (%d)\n", GetLastError());
			return EXIT_FAILURE;
		}
		pDhcpPacket->m_iNbrOpt = pDhcpPacket->m_iRetry = pDhcpPacket->m_iSizeOpt = pDhcpPacket->m_ltime = 0;

		DEBUG_PRINT("<--NewDhcpPacket \n");

		return EXIT_SUCCESS;
	}

	//Free a DCHP Packet
	DWORD FreeDhcpPacket(pDHCP_PACKET& pDhcpPacket)
	{
		DEBUG_PRINT("-->FreeDhcpPacket \n");

		if (pDhcpPacket != NULL)
		{
			if (pDhcpPacket->m_pDhcpMsg != NULL)
				free(pDhcpPacket->m_pDhcpMsg);

			for (int i = 0; i < pDhcpPacket->m_iNbrOpt; i++)
			{
				if (pDhcpPacket->m_ppDhcpOpt[i] != NULL)
				{
					if (pDhcpPacket->m_ppDhcpOpt[i]->OptionValue != NULL)
						free(pDhcpPacket->m_ppDhcpOpt[i]->OptionValue);

					free(pDhcpPacket->m_ppDhcpOpt[i]);
				}
			}
			free(pDhcpPacket);
		}
		return EXIT_SUCCESS;
		DEBUG_PRINT("<--FreeDhcpPacket \n");
	}

	///////////////////////////////////
	//DHCPRawPacket Class Functions
	///////////////////////////////////
	/* DHCPRawPacket Constructor for DHCP client w/o relay */
	DHCPRawPacket::DHCPRawPacket(BYTE(&dhcp_chaddr)[ETHER_ADDR_LEN], bool isRelayOn)
	{
		/* Init DHCP Node */
		if (NewDhcpPacket(this->m_pDhcpPacket) == EXIT_FAILURE)
			this->m_pDhcpPacket = NULL;

		/* Init DHCP Message */
		BYTE dhcp_flags = isRelayOn == TRUE ? DHCP_BROADCAST_FLAG << 7 : DHCP_UNICAST_FLAG << 7;
		USHORT UdpSrcPort = isRelayOn == TRUE ? DHCP_UDP_SPORT : DHCP_UDP_CPORT;

		SetDhcpMessage(DHCP_REQUEST, dhcp_flags, INADDR_ANY, dhcp_chaddr);
		//IPv4 and UDPv4 Headers

		m_pIPv4_HDR = BuildIPv4Hdr(INADDR_ANY, INADDR_BROADCAST, 0, IPPROTO_UDP);
		m_pUDPv4_HDR = BuildUDPv4Hdr(UdpSrcPort, DHCP_UDP_SPORT, 0);
	}

	/* DHCPRawPacket Get Methods */
	pIPv4_HDR DHCPRawPacket::get_pIPv4hdr()
	{
		return m_pIPv4_HDR;
	}

	pUDPv4_HDR DHCPRawPacket::get_pUDPv4hdr()
	{
		return m_pUDPv4_HDR;
	}

	pDHCPv4_HDR DHCPRawPacket::get_pDhcpMsg()
	{
		return m_pDhcpPacket->m_pDhcpMsg;
	}

	pDHCP_PACKET DHCPRawPacket::get_pDhcpPacket()
	{
		return m_pDhcpPacket;
	}

	/*DHCPRawPacket set methods */
	DWORD DHCPRawPacket::SetDhcpMessage(BYTE dhcp_opcode, BYTE dhcp_flags, ULONG dhcp_gip, BYTE(&dhcp_chaddr)[ETHER_ADDR_LEN])
	{
		if (this->m_pDhcpPacket == NULL)
		{
			printf("DHCPRawPacket::SetDhcpMessage Cannot build DHCP message as DHCPPacket is NULL\n");
			return EXIT_FAILURE;
		}

		pDHCPv4_HDR m_pDhcpMsg = this->get_pDhcpMsg();
		m_pDhcpMsg->dhcp_opcode = dhcp_opcode;
		m_pDhcpMsg->dhcp_htype = 0x1;
		m_pDhcpMsg->dhcp_hlen = 0x6;
		m_pDhcpMsg->dhcp_hopcount = 0;

		Sleep(100);
		m_pDhcpMsg->dhcp_xid = 0;
		for (int i = 0; i < 4; i++) {
			srand(GetTickCount());
			int msb = (rand() % 2) << 15;
			m_pDhcpMsg->dhcp_xid += (msb | rand());
		}

		m_pDhcpMsg->dhcp_secs = 0;
		m_pDhcpMsg->dhcp_flags = dhcp_flags << 7;
		m_pDhcpMsg->dhcp_cip = 0;
		m_pDhcpMsg->dhcp_yip = 0;
		m_pDhcpMsg->dhcp_sip = 0;
		m_pDhcpMsg->dhcp_gip = dhcp_gip;

		memset(m_pDhcpMsg->dhcp_chaddr, NULL, 16);
		memcpy(m_pDhcpMsg->dhcp_chaddr, dhcp_chaddr, ETHER_ADDR_LEN);
		memset(m_pDhcpMsg->dhcp_sname, NULL, sizeof(BYTE) * 64);
		memset(m_pDhcpMsg->dhcp_file, NULL, sizeof(BYTE) * 128);

		m_pDhcpMsg->dhcp_magic = htonl(DHCP_MAGIC);

		return EXIT_SUCCESS;
	}

	void DHCPRawPacket::Free()
	{
		free(this->m_pIPv4_HDR);
		free(this->m_pUDPv4_HDR);
		FreeDhcpPacket(this->m_pDhcpPacket);
	}

	void DHCPRawPacket::print()
	{
		char dhcp_cip[INET_ADDRSTRLEN];
		char dhcp_yip[INET_ADDRSTRLEN];
		char dhcp_sip[INET_ADDRSTRLEN];
		char dhcp_gip[INET_ADDRSTRLEN];

		pDHCPv4_HDR m_pDhcpMsg = this->m_pDhcpPacket->m_pDhcpMsg;

		if (sizeof(this->m_pDhcpPacket->m_pDhcpMsg) != NULL)
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
	//DHCPRawLease Class Functions
	/////////////////////////////
	DHCPRawLease::DHCPRawLease(pDHCP_PACKET& pDhcpAck, pDHCP_PACKET& pDhcpRequest, int ClientId)
	{
		SetLease(pDhcpAck, pDhcpRequest, ClientId);
	}

	/* DHCPRawLease SetLease SetMethod */
	void DHCPRawLease::SetLease(pDHCP_PACKET& pDhcpAck, pDHCP_PACKET& pDhcpRequest, int ClientId)
	{
		DEBUG_PRINT("-->DHCPRawLease::SetLease() CLient:%d\n", ClientId);

		pDHCP_LEASE pDhcpLease = (pDHCP_LEASE)malloc(sizeof(DHCP_LEASE));
		this->m_pDhcpLease = pDhcpLease;

		pDhcpLease->m_iClientID = ClientId;
		pDhcpLease->m_pDhcpPacketAck = pDhcpAck;
		pDhcpLease->m_T1 = pDhcpLease->m_T2 = pDhcpRequest->m_ltime; //Assigning the request time first

		ULONG seconds = 0;
		ULONG t1 = 0;
		ULONG t2 = 0;

		//Getting IP address
		inet_ntop(AF_INET, &(pDhcpLease->m_pDhcpPacketAck->m_pDhcpMsg->dhcp_yip), m_LocalAddrIp, INET_ADDRSTRLEN);

		//Compute T1 & T2
		for (int i = 0; i < pDhcpLease->m_pDhcpPacketAck->m_iNbrOpt; i++)
		{
			switch (pDhcpLease->m_pDhcpPacketAck->m_ppDhcpOpt[i]->OptionType)
			{
			case DHCP_RENEWTIME:
				for (int j = 0; j < pDhcpLease->m_pDhcpPacketAck->m_ppDhcpOpt[i]->OptionLength; j++)
					seconds = (seconds * 0x100) + pDhcpLease->m_pDhcpPacketAck->m_ppDhcpOpt[i]->OptionValue[j];
				pDhcpLease->m_T1 += seconds;
				seconds = 0;
				break;
			case DHCP_REBINDTIME:
				for (int j = 0; j < pDhcpLease->m_pDhcpPacketAck->m_ppDhcpOpt[i]->OptionLength; j++)
					seconds = (seconds * 0x100) + pDhcpLease->m_pDhcpPacketAck->m_ppDhcpOpt[i]->OptionValue[j];
				pDhcpLease->m_T2 += seconds;
				seconds = 0;
				break;
			case DHCP_LEASETIME:
				for (int j = 0; j < pDhcpLease->m_pDhcpPacketAck->m_ppDhcpOpt[i]->OptionLength; j++)
					seconds = (seconds * 0x100) + pDhcpLease->m_pDhcpPacketAck->m_ppDhcpOpt[i]->OptionValue[j];

				//Getting the End of the lease
				pDhcpLease->m_TEnd = pDhcpRequest->m_ltime + seconds;
				//Computer T1 and T2 if not provided through DHCP options
				if (pDhcpLease->m_T1 == pDhcpLease->m_T2 == pDhcpRequest->m_ltime)
				{
					DEBUG_PRINT(" DHCPRawLease::SetLease() computing T1 and T2 as not provided\n");
					//T1 : Adding 50% of the lease time 
					t1 = seconds / 2;
					pDhcpLease->m_T1 += t1;

					//T2 : Adding 87.5% of the lease time
					t2 = seconds * 1000 / 875;
					pDhcpLease->m_T2 += t2;
				}
				break;
			case DHCP_SERVIDENT:
				inet_ntop(AF_INET, &(pDhcpLease->m_pDhcpPacketAck->m_ppDhcpOpt[i]->OptionValue[0]), m_ServerAddrIp, INET_ADDRSTRLEN);
				break;
			}
		}

		DEBUG_PRINT("<-- DHCPRawLease::SetLease() CLient:%d\n", ClientId);
	}

	void DHCPRawLease::DeleteLease()
	{
		//ToImplement
	}

	pDHCP_LEASE DHCPRawLease::GetLease()
	{
		return m_pDhcpLease;
	}

	void DHCPRawLease::print()
	{
		if (this->m_pDhcpLease != NULL)
		{
			char dhcp_yip[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &(this->m_pDhcpLease->m_pDhcpPacketAck->m_pDhcpMsg->dhcp_yip), dhcp_yip, INET_ADDRSTRLEN);

			cout << "LeaseGranted:" << endl;
			printf("\tClientID:%d\n\tMyIP:%s\n\tServerIP:%s\n", m_pDhcpLease->m_iClientID, m_LocalAddrIp, m_ServerAddrIp);
			char* t0 = ctime(&m_pDhcpLease->m_pDhcpPacketAck->m_ltime);
			printf("\tLeaseObtened:%s", t0);
			char* t1 = ctime(&m_pDhcpLease->m_T1);
			printf("\tT1:%s", t1);
			char* t2 = ctime(&m_pDhcpLease->m_T2);
			printf("\tT2:%s", t2);
		}
	}
	/////////////////////////////
	//DHCPCLient Class Functions
	/////////////////////////////

	//DHCPRawClient regular mode (BROADCAST)
	DHCPRawClient::DHCPRawClient(int number, int ifindex, bool isRelayOn, string ClientPrefixName, vector<string> StrCustomOpt)
	{
		DEBUG_PRINT("-->DHCPRawClient::DHCPRawClient() ctor m_ClientNumber:%d\n", number);

		m_ClientNumber = number;
		m_IfIndex = ifindex;
		m_pDhcpOffer = m_pDhcpAck = m_pDhcpRequest = NULL;
		m_pDhcpLease = NULL;

		/* Trick to allow sendDhcpRequest() sending multiple DHCP Request in // */
		m_RelayAddrs.push_back("0");
		m_SrvAddrs.push_back("255.255.255.255");
		m_ClientNamePrefix = ClientPrefixName + to_string(m_ClientNumber);

		// setMAc from adapter with ifIndex = m_IfIndex;
		if (setMAC() == EXIT_FAILURE)
		{
			throw "Cannot get MAC address";
		}

		m_DhcpRawPacket = DHCPRawPacket(m_MAC, isRelayOn);
		// Create an unnamed waitable timer for T1 and T2 lease.
		m_hTimer = CreateWaitableTimer(NULL, TRUE, NULL);
		if (NULL == m_hTimer)
		{
			throw "DHCPRawLease::DHCPRawLeaseCreateWaitableTimer failed";
		}

		if (ConvertStrOptToDhpOpt(StrCustomOpt) == EXIT_FAILURE)
			m_numberOfCustomOpts = 0;

		DEBUG_PRINT("<--DHCPRawClient::DHCPRawClient() ctor  m_ClientNumber:%d m_IfIndex:%d m_ClientNamePrefix:%s\n",
			m_ClientNumber, m_IfIndex, m_ClientNamePrefix.c_str());
	}

	//DHCPRawClient RELAY mode
	DHCPRawClient::DHCPRawClient(int number, int ifindex, bool isRelayOn, string ClientPrefixName, vector<string> StrCustomOpt,
		vector<string> RelayAddrs, vector<string> SrvAddrs)
	{
		DEBUG_PRINT("-->DHCPRawClient::DHCPRawClient() ctor m_ClientNumber:%d\n", number);

		//Attributes
		//m_IsReceiver = isReceiver;
		//If not DHCP SenderReceiver
		m_ClientNumber = number;
		m_IfIndex = ifindex;
		m_pDhcpOffer = m_pDhcpAck = m_pDhcpRequest = NULL;
		m_pDhcpLease = NULL;

		m_ClientNamePrefix = ClientPrefixName + to_string(m_ClientNumber);

		// setMAc from adapter with ifIndex = m_IfIndex;
		if (setMAC() == EXIT_FAILURE)
		{
			throw "Cannot get MAC address";
		}

		m_DhcpRawPacket = DHCPRawPacket(m_MAC, isRelayOn);

		m_gRelayMode = isRelayOn;
		m_RelayAddrs = RelayAddrs;
		m_SrvAddrs = SrvAddrs;

		// Create an unnamed waitable timer for T1 and T2 lease.
		m_hTimer = CreateWaitableTimer(NULL, TRUE, NULL);
		if (NULL == m_hTimer)
		{
			throw "DHCPRawLease::DHCPRawLeaseCreateWaitableTimer failed";
		}

		if (ConvertStrOptToDhpOpt(StrCustomOpt) == EXIT_FAILURE)
			m_numberOfCustomOpts = 0;

		DEBUG_PRINT("<--DHCPRawClient::DHCPRawClient() ctor  m_ClientNumber:%d m_IfIndex:%d m_ClientNamePrefix:%s\n",
			m_ClientNumber, m_IfIndex, m_ClientNamePrefix.c_str());
		//this->print();
	}

	//DHCPRawClient Receiver
	DHCPRawClient::DHCPRawClient(int number, bool isReceiver, bool bIsRealyOn)
	{
		DEBUG_PRINT("-->DHCPRawClient::DHCPRawClient() ctor Receiver:%d\n", number);

		//Attributes
		m_IsReceiver = isReceiver;
		m_gRelayMode = bIsRealyOn;
		m_ClientNumber = number;
		m_IfIndex = 0;
		m_pDhcpOffer = m_pDhcpAck = m_pDhcpRequest = NULL;
		m_pDhcpLease = NULL;

		DEBUG_PRINT("-->DHCPRawClient::DHCPRawClient() ctor Receiver\n");
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
			m_DhcpRawPacket.print();
		}
	}

	int DHCPRawClient::getClientNumber()
	{
		return m_ClientNumber;
	}

	DWORD DHCPRawClient::ConvertStrOptToDhpOpt(std::vector<string> StrCustomOpt)
	{
		DEBUG_PRINT("-->DHCPRawClient::ConvertStrOptToDhpOpt()\n");

		int tmp = 0;
		int index = 0;

		if (StrCustomOpt.size() < 2)
			return EXIT_FAILURE;

		while (index < StrCustomOpt.size())
		{
			StrCustomOpt[index].erase(remove_if(StrCustomOpt[index].begin(), StrCustomOpt[index].end(), isspace), StrCustomOpt[index].end());

			PDHCP_OPT pDhcpOpt_Current = (PDHCP_OPT)malloc(sizeof(DHCP_OPT));
			pDhcpOpt_Current->OptionType = strtoul(StrCustomOpt[index].c_str(), 0, 0);
			index++;

			pDhcpOpt_Current->OptionLength = strtoul(StrCustomOpt[index].c_str(), 0, 0);
			index++;

			if (index + pDhcpOpt_Current->OptionLength > StrCustomOpt.size())
				return EXIT_FAILURE;

			pDhcpOpt_Current->OptionValue = (PBYTE)malloc(sizeof(BYTE) * pDhcpOpt_Current->OptionLength);

			for (int i = 0; i < pDhcpOpt_Current->OptionLength; i++)
			{
				pDhcpOpt_Current->OptionValue[i] = strtoul(StrCustomOpt[index].c_str(), 0, 0);;
				index++;
			}
			index += pDhcpOpt_Current->OptionLength + 2;

			//Add opts to the list
			m_pCustomDhcpOpts.push_back(pDhcpOpt_Current);

#ifdef _DEBUG
			PDHCP_OPT temp = NULL;
			for (auto it = m_pCustomDhcpOpts.begin(); it != m_pCustomDhcpOpts.end(); it++)
			{
				temp = *it;
				printf("OptionType=%X\nOptionLength=%X\nOptionValue=", temp->OptionType, temp->OptionLength);
				for (int j = 0; j < temp->OptionLength; j++)
					printf("%X\n", temp->OptionValue[j]);
			}
#endif // DEBUG

			m_numberOfCustomOpts++;
		}

		DEBUG_PRINT("<--DHCPRawClient::ConvertStrOptToDhpOpt()\n");
		return EXIT_SUCCESS;
	}

	DWORD DHCPRawClient::setMAC()
	{
		DEBUG_PRINT("-->DHCPRawClient::SetMac()\n");
		DWORD status = EXIT_FAILURE;

		if (GetAdapterMacByIndex(m_IfIndex, m_MAC) == EXIT_SUCCESS)
		{
			m_MAC[ETHER_ADDR_LEN - 1] = m_ClientNumber & 0xFF;
			m_MAC[ETHER_ADDR_LEN - 2] = (m_ClientNumber >> 8);
			status = ERROR_SUCCESS;
		}

		DEBUG_PRINT("<--DHCPRawClient::SetMac() Status:%d\n", status);
		return status;
	}

	DWORD DHCPRawClient::SetStateTransition(int NewState)
	{

		DEBUG_PRINT("--> SetStateTransition from %d to %d\n", m_StateTransition, NewState);

		if (NewState >= StateTransition::Init && NewState <= StateTransition::Releasing)
			m_StateTransition = NewState;
		else
			return EXIT_FAILURE;

		DEBUG_PRINT("<-- SetStateTransition\n");;

		return EXIT_SUCCESS;
	}


	/* DHCP Client Thread:
		* Wait DHCP Receiver to be ready
		* Sent DHCP Discover (pass it to relay by inserted it to the Queue if needed)
		* Consume any DHCP Offer and reply accordingly -> signaled by a completion event set by DHCPReceiver() thread
		* do 3 restransmit
		* Handle the DhcpClient state mahcine
	*/
	DWORD DHCPRawClient::DhcpClient()
	{
		DEBUG_PRINT("--> DHCPRawClient::DhcpClient() CLient:%d\n", m_ClientNumber);
		DWORD dwWaitResultOnSocketEvent;
		DWORD dwWaitOnCompletionRequest;

		pDHCP_PACKET pDhcpReply = NULL;
		pDHCP_PACKET pDhcpAck = NULL;

		/* Wait the DHCP Receiver is started*/
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

		//Event g_hSocketWaitEvent has been signaled
		printf("DHCPRawClient::DhcpClient() CLient:%d is starting\n", m_ClientNumber);

		do
		{
			//Checking DHCP client state machine 
			switch (m_StateTransition)
			{
			case StateTransition::Init:
				//Build DHCP Discover
				build_dhpc_request();
				//Transition to selecting
				SetStateTransition(m_StateTransition + 1);
				break;
				//Selecting is implementing into the receive part see below after the wait on completion event

			case StateTransition::Requesting:
				//TODO : implementing a way to collect multiple OFFER before selecting
				// And ARP request and DECLINE eventually
				if (m_pDhcpOffer != NULL)
				{
					//Build DHCP Request following OFFER
					build_dhpc_request();
				}

				break;
			case StateTransition::Bound:
				//CreateLease
				m_pDhcpRequest->m_iRetry = 0;

				m_DhcpRawLease = DHCPRawLease(m_pDhcpAck, m_pDhcpRequest, m_ClientNumber);
				m_pDhcpLease = m_DhcpRawLease.GetLease();
				//Sleep(5 * m_ClientNumber);
				m_DhcpRawLease.print();

				if (g_DhcpAutoRelease)
				{
					printf("DHCPRawClient::DhcpClient(): CLient:%d will send DHCPRelease in 5 secs.\n", m_ClientNumber);
					Sleep(5000);

					//Transitionning to Releasing
					SetStateTransition(StateTransition::Releasing);
					build_dhpc_request();
					break;
				}

				if (WaitOnTimer(this->m_hTimer, m_pDhcpLease->m_T1, "Waiting for T1 to be expired..."))
					printf("ERROR: Call to WaitOnTimer failed\n");
				else
					printf("DHCPRawClient::DhcpClient(): T1 is expired...\n");

				//Transition to Renewing
				SetStateTransition(m_StateTransition + 1);

				break;
			case StateTransition::Renewing:

				if (m_pDhcpRequest->m_iRetry == DHCP_RETRANSMIT_COUNT - 1) // If no ACK received at T1, then waits T2 and transition to rebinding
				{
					//In renewing we transitionne to rebinding after T2 if not answer received
					m_pDhcpRequest->m_iRetry = 0;

					if (WaitOnTimer(this->m_hTimer, m_pDhcpLease->m_T2, "Waiting for T2 to be expired..."))
						printf("ERROR: Call to WaitOnTimer failed\n");
					else
						printf("DHCPRawClient::DhcpClient(): T2 is expired...\n");

					//Transitionning to rebinding state
					SetStateTransition(m_StateTransition + 1);
				}
				//Otherwise try to renew
				build_dhpc_request();

				break;
			case StateTransition::Rebinding:
				if (m_pDhcpRequest->m_iRetry == DHCP_RETRANSMIT_COUNT - 1) // If no ACK received at T1, then waits T2 and transition to rebinding
				{
					//In renewing we transitionne to rebinding after T2 if not answer received
					m_pDhcpRequest->m_iRetry = 0;

					if (WaitOnTimer(this->m_hTimer, m_pDhcpLease->m_T2, "Waiting until the lease is expired..."))
						printf("ERROR: Call to WaitOnTimer failed\n");
					else
						printf("DHCPRawClient::DhcpClient(): Lease is expired...\n");

					//Transitionning to Init
					SetStateTransition(StateTransition::Init);
					//Do not go to DISCOVER AGAIN just the exit the thread...
					return EXIT_FAILURE;
				}
				break;
			}

			//Insert Request in Q in order to let DHCP receiver thread setting the completion event
			InsertLock(DHCP_REQUEST - 1, m_pDhcpRequest);
			//Send request on the Wire
			SendDhcpRequest();
			//if DHCP Release sent hence exit
			if (m_StateTransition == StateTransition::Releasing)
				goto cleanup;

			//waiting until the completion event is signaled by DHCPReceiver() thread
			dwWaitOnCompletionRequest = WaitForSingleObject(
				m_pDhcpRequest->hCompletionEvent, // event handle
				DHCP_RETRANSMIT_TIMEOUT);    // 

			switch (dwWaitOnCompletionRequest)
			{
				// Event object was signaled
			case WAIT_OBJECT_0:
				//Extrat the Reply associated with m_pDhcpRequest
				pDhcpReply = ExtractElement(DHCP_REPLY - 1, m_pDhcpRequest);

				DEBUG_PRINT("DHCPRawClient::DhcpClient()  DCHP Reply received: MsgType=%d\n", pDhcpReply->m_ppDhcpOpt[0]->OptionValue[0]);

				switch ((int)pDhcpReply->m_ppDhcpOpt[0]->OptionValue[0])
				{
				case DHCP_MSGOFFER:
					if (m_StateTransition == StateTransition::Selecting)
					{
						m_pDhcpOffer = pDhcpReply;
						//Transition to requesting
						SetStateTransition(m_StateTransition + 1);
					}
					//else
					//{//DROP Duplicate
					//	free(pDhcpReply);
					//}
					break;

				case DHCP_MSGACK:
					if (m_StateTransition != StateTransition::Bound)
					{
						//Store new ACK
						m_pDhcpAck = pDhcpReply;
						if (m_StateTransition < StateTransition::Bound)
							SetStateTransition(m_StateTransition + 1);
						else
							SetStateTransition(StateTransition::Bound);

					}
					//else
					//{//DROP Duplicate
					//	free(pDhcpReply);
					//}
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

			//Dequeue the request if present
			if (FindElement(DHCP_REQUEST - 1, m_pDhcpRequest))
				m_pDhcpRequest = ExtractElement(DHCP_REQUEST - 1, m_pDhcpRequest);

		} while (m_pDhcpRequest->m_iRetry < DHCP_RETRANSMIT_COUNT);//LeaseNotGranter or Retry > 3 


		DEBUG_PRINT("--> DHCPRawClient::DhcpClient() CLient:%d\n", m_ClientNumber);

		//free(m_pDhcpRequest);

	cleanup:
	//	m_DhcpRawPacket.Free();
		//if (pDhcpReply != NULL)
		//	free(pDhcpReply);

		//if (m_pDhcpAck != NULL)
		//	free(m_pDhcpAck);

		//if (m_pDhcpOffer != NULL)
		//	free(m_pDhcpOffer);


		return EXIT_SUCCESS;
	}

	/* This routine a DHCP Request... The request is build based on the current StateTransition*/
	DWORD DHCPRawClient::build_dhpc_request()
	{
		DEBUG_PRINT("--> DHCPRawClient::build_dhpc_request CLient:%d FSM:%d\n", m_ClientNumber, this->m_StateTransition);

		string pchDomainName; // = NULL;
		string pcClientFQDN;// = (char*)malloc(sizeof(char) * m_ClientNamePrefix.size() + 255);
		USHORT iNbrOpt = 0;
		USHORT iDhcpOptSize = 0;
		USHORT iDhcpOpt = 0;
		int DhcpMsgType = DHCP_MSGREQUEST;
		//TODO Let user custom this from command line with a vector<byte>
		vector<int> rgb_ParameterRequestList = { DHCP_SUBNETMASK, DHCP_BROADCASTADDR, DHCP_ROUTER, DHCP_DOMAINNAME, DHCP_DNS };
		pDHCP_PACKET pDhcpReply = NULL;
		PDHCP_OPT pDhcpOpt_Current = NULL;
		pIPv4_HDR myIPv4Hdr = NULL;

		DHCPRawPacket _DHCPRawPacket = DHCPRawPacket::DHCPRawPacket(this->m_MAC, m_gRelayMode);
		pDHCP_PACKET DhcpPacket = _DHCPRawPacket.get_pDhcpPacket();

		pDHCP_PACKET m_pDhcpPreviousRequest = m_pDhcpRequest;

		switch (this->m_StateTransition)
		{
		case StateTransition::Init:
			iNbrOpt = DHCP_OPT_NBR_DISCVOVER;
			DhcpMsgType = DHCP_MSGDISCOVER;
			//DhcpPacket->m_pDhcpMsg = this->m_DhcpRawPacket.get_pDhcpMsg();
			DhcpPacket->m_iRetry = 0;
			break;
		case StateTransition::Requesting:
			pDhcpReply = m_pDhcpOffer;
			iDhcpOptSize = m_pDhcpPreviousRequest->m_iSizeOpt;
			iNbrOpt = m_pDhcpPreviousRequest->m_iNbrOpt;
			if (pDhcpReply->m_pDhcpMsg->dhcp_sip != 0)
				iNbrOpt++;

			iNbrOpt += 2;
			DhcpPacket->m_iRetry = 0;

			break;
		case StateTransition::Renewing:
			pDhcpReply = m_pDhcpOffer;
			iDhcpOptSize = m_pDhcpPreviousRequest->m_iSizeOpt;
			iNbrOpt = m_pDhcpPreviousRequest->m_iNbrOpt;
			if (pDhcpReply->m_pDhcpMsg->dhcp_sip != 0)
				iNbrOpt++;

			iNbrOpt += 2;

			DhcpPacket->m_iRetry = m_pDhcpPreviousRequest != NULL ? m_pDhcpPreviousRequest->m_iRetry : 0;
			break;
		case StateTransition::Releasing:

			pDhcpReply = m_pDhcpOffer;
			iNbrOpt = 3; // MsgType 53 + SrvID 54 + ClientID 61 + END 255 (End is not count as opt is the computation)... just added before padding
			DhcpPacket->m_pDhcpMsg->dhcp_cip = pDhcpReply->m_pDhcpMsg->dhcp_yip;
			//
			myIPv4Hdr = m_DhcpRawPacket.get_pIPv4hdr();
			break;
		default:
			pDhcpReply = this->m_pDhcpAck;
			iNbrOpt = m_pDhcpPreviousRequest->m_iNbrOpt;
			if (pDhcpReply->m_pDhcpMsg->dhcp_sip != 0)
				iNbrOpt++;

			iNbrOpt += 2;

			DhcpPacket->m_iRetry = m_pDhcpPreviousRequest != NULL ? m_pDhcpPreviousRequest->m_iRetry : 0;
			break;
		}

		//Something wrong here....
		if (DhcpPacket == NULL)
			return EXIT_FAILURE;

		//Custom DHCP opts
		if (m_numberOfCustomOpts > 0)
			iNbrOpt += m_numberOfCustomOpts;
				
		//Allocate space  DhcpOptions + 1 for the END OPT
		DhcpPacket->m_ppDhcpOpt = (PDHCP_OPT*)malloc(sizeof(PDHCP_OPT) * iNbrOpt);
		for (int i = 0; i < iNbrOpt; i++)
			DhcpPacket->m_ppDhcpOpt[i] = (PDHCP_OPT)malloc(sizeof(DHCP_OPT));

		if (this->m_StateTransition == StateTransition::Init)
		{
			DEBUG_PRINT("--> DHCPRawClient::build_dhpc_request DISCOVER\n");

			iDhcpOptSize += build_option53(DHCP_MSGDISCOVER, DhcpPacket->m_ppDhcpOpt[iDhcpOpt]);
			iDhcpOpt++;

			iDhcpOptSize += build_option_61(DhcpPacket->m_pDhcpMsg->dhcp_chaddr, DhcpPacket->m_ppDhcpOpt[iDhcpOpt]);
			iDhcpOpt++;
		
			iDhcpOptSize += build_option_55(rgb_ParameterRequestList, DhcpPacket->m_ppDhcpOpt[iDhcpOpt]);
			iDhcpOpt++;
		}
		else if (this->m_StateTransition == StateTransition::Releasing)
		{
			DEBUG_PRINT("--> DHCPRawClient::build_dhpc_request RELEASE\n");

			iDhcpOptSize += build_option53(DHCP_MSGRELEASE, DhcpPacket->m_ppDhcpOpt[iDhcpOpt]);
			iDhcpOpt++;

			iDhcpOptSize += build_option50_54(DHCP_SERVIDENT, htonl(pDhcpReply->m_pDhcpMsg->dhcp_sip), DhcpPacket->m_ppDhcpOpt[iDhcpOpt]);
			iDhcpOpt++;

			iDhcpOptSize += build_option_61(DhcpPacket->m_pDhcpMsg->dhcp_chaddr, DhcpPacket->m_ppDhcpOpt[iDhcpOpt]);
			iDhcpOpt++;
		}
		else
		{
			//Something wrong here.... 
			if (pDhcpReply == NULL || m_pDhcpPreviousRequest == NULL)
				return EXIT_FAILURE;

			//DhcpPacket->m_pDhcpMsg = (pDHCPv4_HDR)malloc(sizeof(DHCPv4_HDR));
			memcpy(DhcpPacket->m_pDhcpMsg, pDhcpReply->m_pDhcpMsg, sizeof(DHCPv4_HDR));
			DhcpPacket->m_pDhcpMsg->dhcp_opcode = DHCP_REQUEST;
			DhcpPacket->m_pDhcpMsg->dhcp_yip = 0;

			for (int i = 0; i < pDhcpReply->m_iNbrOpt; i++)
			{
				//Get the domain name from the DHCP Reply
				if (pDhcpReply->m_ppDhcpOpt[i]->OptionType == DHCP_DOMAINNAME)
				{
					pchDomainName = string((const char*)pDhcpReply->m_ppDhcpOpt[i]->OptionValue, pDhcpReply->m_ppDhcpOpt[i]->OptionLength);
				}
			}

			for (int i = 0; i < m_pDhcpPreviousRequest->m_iNbrOpt-1; i++)
			{
				DhcpPacket->m_ppDhcpOpt[i] = m_pDhcpPreviousRequest->m_ppDhcpOpt[i];
				//iDhcpOptSize += m_pDhcpPreviousRequest->m_ppDhcpOpt[i]->OptionLength + 2;

				switch (m_pDhcpPreviousRequest->m_ppDhcpOpt[i]->OptionType)
				{
				case DHCP_MESSAGETYPE:
					iDhcpOptSize += build_option53(DhcpMsgType, DhcpPacket->m_ppDhcpOpt[i]);
					break;
				}
				iDhcpOpt++;
			}

			pcClientFQDN = m_ClientNamePrefix + "." + pchDomainName;

			//sprintf(pcClientFQDN, "%s%d.%s", m_ClientNamePrefix, m_pDhcpReply->m_pDhcpMsg->dhcp_chaddr[5], pchDomainName);

			iDhcpOptSize += build_option50_54(DHCP_REQUESTEDIP, htonl(pDhcpReply->m_pDhcpMsg->dhcp_yip), DhcpPacket->m_ppDhcpOpt[iDhcpOpt]);
			iDhcpOpt++;

			DEBUG_PRINT("OPTION81: %s\n", pcClientFQDN.c_str());

			iDhcpOptSize += build_option_81((char*)pcClientFQDN.c_str(), DhcpPacket->m_ppDhcpOpt[iDhcpOpt]);
			iDhcpOpt++;

			// adding srv identity
			if (pDhcpReply->m_pDhcpMsg->dhcp_sip > 0)
			{
				iDhcpOptSize += build_option50_54(DHCP_SERVIDENT, htonl(pDhcpReply->m_pDhcpMsg->dhcp_sip), DhcpPacket->m_ppDhcpOpt[iDhcpOpt]);
				iDhcpOpt++;
			}
		}

		if (m_numberOfCustomOpts > 0)
		{
			DEBUG_PRINT("Custom option(s) detected\n");

			for (auto it = m_pCustomDhcpOpts.begin(); it != m_pCustomDhcpOpts.end(); it++)
			{
				pDhcpOpt_Current = *it;

				DhcpPacket->m_ppDhcpOpt[iDhcpOpt]->OptionType = pDhcpOpt_Current->OptionType;
				DhcpPacket->m_ppDhcpOpt[iDhcpOpt]->OptionLength = pDhcpOpt_Current->OptionLength;

				DhcpPacket->m_ppDhcpOpt[iDhcpOpt]->OptionValue = (PBYTE)malloc(sizeof(BYTE) * pDhcpOpt_Current->OptionLength);

				memcpy(DhcpPacket->m_ppDhcpOpt[iDhcpOpt]->OptionValue, pDhcpOpt_Current->OptionValue, sizeof(BYTE) * pDhcpOpt_Current->OptionLength);
				iDhcpOptSize += pDhcpOpt_Current->OptionLength + 2;
				iDhcpOpt++;
			}
		}

		//Adding space for END OPT
		//DhcpPacket->m_ppDhcpOpt[iDhcpOpt]->OptionType = DHCP_END;
		DhcpPacket->m_pDhcpMsg->dhcp_sip = 0;
		//Relay mode 
		DhcpPacket->m_pDhcpMsg->dhcp_gip = 0;//m_gRelayMode == TRUE ? inet_addr(m_RelayAddr.c_str()) : 0;

		DhcpPacket->m_iSizeOpt = iDhcpOptSize;
		DhcpPacket->m_iNbrOpt = iDhcpOpt+1;
		DhcpPacket->m_ltime = 0;

		// Assigning the DHCPpacket to the DHCPRawclient Object
		m_pDhcpRequest = DhcpPacket;

		DhcpPacket = NULL;
		//_DHCPRawPacket.Free();

		DEBUG_PRINT("<-- DHCPRawClient::build_dhpc_request CLient:%d\n", m_ClientNumber);

		return EXIT_SUCCESS;
	}

	/* This routine is called by DHCPReceiver() thread to signaled DHCPClient() thread that a reply has been received*/
	DWORD DHCPRawClient::SetDHCPRequestCompletionEvent(int bucket, pDHCP_PACKET pDhcpReply)
	{
		DEBUG_PRINT("--> DHCPRawClient::SetDHCPRequestCompletionEvent CLient:%d\n");

		pDHCP_PACKET pDhcpRequest = FindElement(bucket, pDhcpReply);
		if (pDhcpRequest != NULL)
		{
			if ((pDhcpRequest->m_pDhcpMsg->dhcp_xid == pDhcpReply->m_pDhcpMsg->dhcp_xid))
			{
				DEBUG_PRINT("DHCPRawClient::SetDHCPRequestCompletionEvent SetEvent RequestXID=%.8X ReplyXID=%.8X\n",
					ntohl((pDhcpRequest->m_pDhcpMsg->dhcp_xid)), ntohl((pDhcpReply->m_pDhcpMsg->dhcp_xid)));
				//Sets the event in order to let the sending thread to start his work
				if (!SetEvent(pDhcpRequest->hCompletionEvent))
				{
					printf("DHCPRawClient::SetCompletionEvent failed (%d)\n", GetLastError());
				}
			}
			else
			{
				DEBUG_PRINT("DHCPRawClient::SetDHCPRequestCompletionEvent DROPPING DHCP REPLY due to XID mismatch\n");
				free(pDhcpReply); //Associate Request not found ... Silenty DROP the packet
			}

		}
		DEBUG_PRINT("<-- DHCPRawClient::SetDHCPRequestCompletionEvent CLient:%d\n");

		return EXIT_FAILURE;
	}

	//WorkerThread entry point 
	void DHCPRawClient::Run()
	{
		if (this->m_IsReceiver)
		{
			this->DhcpReceiver();
		}
		else
		{
			this->DhcpClient();
		}
	}

	/* DHCP Receiver Thread:
		* Create a socket and listen for incoming DHCP Packet (port :68 in classic mode or :67 in rellay mode)
		* Insert DHCP Packet (Reply) to the Q and call SetCompletionEvent to signaled the DHCPClient() thread
	*/
	DWORD DHCPRawClient::DhcpReceiver()
	{
		DEBUG_PRINT("--> DHCPRawClient::DhcpReceiver()\n");

		int iResult = 0;
		int i = 0;
		int optval = 1;
		int SenderAddrSize = DHCP_MAX_PACKET_SIZE;
		int recvbytes = 0;
		int request = 0;
		int optname = SO_BROADCAST;

		struct timeval timeout;

		pDHCP_PACKET pDhcpReply = NULL;
		USHORT cpt;
		USHORT nbrOpt;

		SOCKET RcvSocket = NULL;
		SOCKADDR_STORAGE rcvfrom;
		WSADATA wsaData = { 0 };
		fd_set readfs;

		char* RecvBuff = (char*)(malloc(sizeof(char) * DHCP_MAX_PACKET_SIZE));

		/* Initialize Winsock DLL usage */
		iResult = WSAStartup(MAKEWORD(2, 0), &wsaData);
		if (iResult != 0)
		{
			printf("DHCPRawClient::DhcpReceiver(): Error WSAStartup() call failed: %d\n", WSAGetLastError());
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
			printf("DHCPRawClient::DhcpReceiver(): Error socket() call failed: %d\n", WSAGetLastError());
			goto cleanup;
		}

		optname = m_gRelayMode == TRUE ? SO_EXCLUSIVEADDRUSE : SO_BROADCAST;

		DEBUG_PRINT("DHCPRawClient::DhcpReceiver() RelayMode=%d\n", m_gRelayMode);
		//Set SO_EXCLUSIVEADDRUSE in case of Relay mode
		iResult = setsockopt(RcvSocket, SOL_SOCKET, optname, (char*)&optval, sizeof(optval));
		if (iResult == SOCKET_ERROR) {
			printf("DHCPRawClient::DhcpReceiver(): Error setsockopt() call failed : %d\n", WSAGetLastError());
			goto cleanup;
		}

		//----------------------
		// Bind the socket.
		iResult = bind(RcvSocket, (SOCKADDR*)&rcvfrom, sizeof(rcvfrom));
		if (iResult == SOCKET_ERROR)
		{
			printf("DHCPRawClient::DhcpReceiver(): Error bind() call failed : %d\n", WSAGetLastError());
			goto cleanup;
		}

		//Sets the g_hSocketWaitEvent to wake up DHCP Clients threads... We are ready to receive...
		if (!SetEvent(g_hSocketWaitEvent))
		{
			printf("DHCPRawClient::DhcpReceiver(): SetEvent failed (%d)\n", GetLastError());
			goto cleanup;
		}

		//while (!bEndOfProgram)
		for (;;)
		{
			//timeout.tv_sec = 1; /* 1 s */
			timeout.tv_usec = 5 * 100 * 1000; /* 500 ms */
			timeout.tv_sec = 10; /* 500 ms */


			FD_ZERO(&readfs);      /* clears readfs */
			FD_SET(RcvSocket, &readfs); /* adds a stream */

			DEBUG_PRINT("DHCPRawClient::DhcpReceiver(): Waiting on select()....\n");
			iResult = select((int)RcvSocket, &readfs, NULL, NULL, &timeout);

			switch (iResult)
			{
			case 0:
				//if all DHCP clients are exited, then exit as well
				if (g_DhcpReceiverAlone)
				{
					printf("DHCPRawClient::DhcpReceiver():  select() TimeOut End of program\n");
					goto cleanup;
				}
				break;
			case SOCKET_ERROR:
				printf("DHCPRawClient::DhcpReceiver():  select() failed\n");
				break;
			}

			if (FD_ISSET(RcvSocket, &readfs))
			{
				DEBUG_PRINT("DHCPRawClient::DhcpReceiver(): DHCP msg received\n");

				recvbytes = recvfrom(RcvSocket, RecvBuff, DHCP_MAX_PACKET_SIZE, 0, (SOCKADDR*)&rcvfrom, &SenderAddrSize);

				if (recvbytes == SOCKET_ERROR)
					goto cleanup;

				if (NewDhcpPacket(pDhcpReply) == EXIT_FAILURE)
				{
					printf("DHCPRawClient::DhcpReceiver():  error creating DHCP reply envelope\n");
					break;
				}
				memcpy(pDhcpReply->m_pDhcpMsg, RecvBuff, sizeof(DHCPv4_HDR));;

				if (recvbytes >= DHCP_MIN_PACKET_SIZE)
				{
					DEBUG_PRINT("DHCPRawClient::DhcpReceiver(): DhcpMsg Received Bytes=%d\n", recvbytes);

					cpt = DHCPv4_H;
					nbrOpt = 0;
					while (cpt < recvbytes - 1)
					{
						cpt += (2 + RecvBuff[cpt + 1]);
						nbrOpt++;
					}
					pDhcpReply->m_iSizeOpt = cpt - DHCPv4_H;
					pDhcpReply->m_ppDhcpOpt = (PDHCP_OPT*)malloc(sizeof(PDHCP_OPT) * nbrOpt);

					cpt = DHCPv4_H;
					for (int i = 0; i < nbrOpt; i++)
					{
						pDhcpReply->m_ppDhcpOpt[i] = (PDHCP_OPT)malloc(sizeof(DHCP_OPT));
						pDhcpReply->m_ppDhcpOpt[i]->OptionType = RecvBuff[cpt];
						pDhcpReply->m_ppDhcpOpt[i]->OptionLength = RecvBuff[cpt + 1];
						pDhcpReply->m_ppDhcpOpt[i]->OptionValue = (PBYTE)malloc((sizeof(BYTE) * pDhcpReply->m_ppDhcpOpt[i]->OptionLength));
						for (int j = 0; j < pDhcpReply->m_ppDhcpOpt[i]->OptionLength; j++)
							pDhcpReply->m_ppDhcpOpt[i]->OptionValue[j] = RecvBuff[cpt + 2 + j];

						cpt += (2 + RecvBuff[cpt + 1]);
					}
					pDhcpReply->m_iNbrOpt = nbrOpt;

					//Timestamp the message before inserting it
					time(&(pDhcpReply->m_ltime));

					//Insert Reply and signal compleation event
					InsertLock(DHCP_REPLY - 1, pDhcpReply);
					SetDHCPRequestCompletionEvent(DHCP_REQUEST - 1, pDhcpReply);
				}
				else
				{
					DEBUG_PRINT("DHCPRawClient::DhcpReceiver(): PAkcet is dropeped because it exceeded DHCP_MAX_PACKET_SIZE:%d\n", DHCP_MAX_PACKET_SIZE);
					free(pDhcpReply);
				}

				iResult = WSAGetLastError(); // iResult turns 10057
												//Which means the socket isnt connected
				//recvbytes = recvbytes > DHCP_MAX_PACKET_SIZE ? recvbytes : DHCP_MAX_PACKET_SIZE;

				ZeroMemory(RecvBuff, sizeof(char) * DHCP_MAX_PACKET_SIZE);
			}
		}

		if (closesocket(RcvSocket) == SOCKET_ERROR)
		{
			printf("DHCPRawClient::DhcpReceiver(): Error closesocket() call failed : %d\n", WSAGetLastError());
			goto cleanup;
		}

	cleanup:
		closesocket(RcvSocket);

		if (RecvBuff != NULL)
			free(RecvBuff);

		if (pDhcpReply != NULL)
			free(pDhcpReply);

		WSACleanup();
		DEBUG_PRINT("<-- DHCPRawClient::Receive()\n");

		return EXIT_SUCCESS;
	}

	/*
		Send DHCPPacket on the wire:
			* Doing the relay operation by send multiple time the same request from all configured RelayAddr and all configured Dhcp Srv
	*/
	DWORD DHCPRawClient::SendDhcpRequest()
	{
		DEBUG_PRINT("--> SendDhcpRequest()\n");

		SOCKET sock = NULL;
		SOCKADDR_STORAGE src_sockaddr, dst_sockaddr;
		WSADATA wsaData = { 0 };

		pDHCP_PACKET DhcpPacket = this->m_pDhcpRequest;

		int iResult = 0, optval;
		pIPv4_HDR myIPv4Hdr = NULL;
		pUDPv4_HDR myUDPv4hdr = NULL;
		USHORT DHCPv4_HDR_len = sizeof(DHCPv4_HDR);
		USHORT dhcp_opt_len = DhcpPacket->m_iSizeOpt+1;//> 0 ? DhcpPacket->m_iSizeOpt+1: 1; //DHCP_END OPTION

		USHORT dhcp_msg_len = DHCPv4_HDR_len + dhcp_opt_len;
		USHORT padding = dhcp_msg_len < DHCP_MIN_PACKET_SIZE ? DHCP_MIN_PACKET_SIZE - dhcp_msg_len : 0;
		dhcp_msg_len += padding;
		USHORT udp_len = sizeof(UDPv4_HDR) + dhcp_msg_len;
		USHORT ip_len = sizeof(IPv4_HDR) + udp_len;
		
		char* buf = (char*)malloc(sizeof(char) * DHCP_MAX_PACKET_SIZE);
		ZeroMemory(buf, sizeof(char) * DHCP_MAX_PACKET_SIZE);
		char* OptBuf = NULL;

		//Timestamp the message before sending it
		myIPv4Hdr = m_DhcpRawPacket.get_pIPv4hdr();
		myUDPv4hdr = m_DhcpRawPacket.get_pUDPv4hdr();
		myIPv4Hdr->ip_totallength = htons(ip_len);
		myUDPv4hdr->udp_length = htons(udp_len);

		//DEBUG_PRINT("SendDhcpRequest() g_bRelayMode=%d\n", g_bRelayMode);
		iResult = WSAStartup(MAKEWORD(2, 0), &wsaData);
		if (iResult != 0)
		{
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

		if (m_gRelayMode == FALSE)
		{
			if (myIPv4Hdr->ip_destaddr == INADDR_BROADCAST)
			{
				if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char*)&optval, sizeof(optval)) == SOCKET_ERROR)
				{
					printf("SendDhcpRequest() : setsockopt call failed with error %d\n", WSAGetLastError());
					goto cleanup;
				}
			}
		}

		for (int i = 0; i < m_RelayAddrs.size(); i++)
		{
			myIPv4Hdr->ip_srcaddr = inet_addr(m_RelayAddrs[i].c_str());
			DhcpPacket->m_pDhcpMsg->dhcp_gip = inet_addr(m_RelayAddrs[i].c_str());

			for (int j = 0; j < m_SrvAddrs.size(); j++)
			{

				if (m_StateTransition == StateTransition::Releasing)
				{
					myIPv4Hdr->ip_srcaddr = DhcpPacket->m_pDhcpMsg->dhcp_cip;
					myIPv4Hdr->ip_destaddr = this->m_pDhcpOffer->m_pDhcpMsg->dhcp_sip;
				}
				else
					myIPv4Hdr->ip_destaddr = inet_addr(m_SrvAddrs[j].c_str());

				memcpy(buf, myIPv4Hdr, sizeof(IPv4_HDR));
				memcpy(buf + sizeof(IPv4_HDR), myUDPv4hdr, sizeof(UDPv4_HDR));
				memcpy(buf + sizeof(IPv4_HDR) + sizeof(UDPv4_HDR), DhcpPacket->m_pDhcpMsg, DHCPv4_HDR_len);

				DEBUG_PRINT("SendDhcpRequest(): SEND PACKET ON WIRE SrcIp:%.4X:%d DStIp:%.4X:%d\n", myIPv4Hdr->ip_srcaddr,
					myUDPv4hdr->src_port, myIPv4Hdr->ip_destaddr, myUDPv4hdr->dst_port);

				if (dhcp_opt_len > 0 && DhcpPacket->m_iNbrOpt > 0)
				{
					OptBuf = (char*)malloc(sizeof(char) * dhcp_opt_len);
					ZeroMemory(OptBuf, sizeof(char) * dhcp_opt_len);

					USHORT offset = 0;
					//change DHCP_OPT to PDHCP_OPT 
					for (int i = 0; i < DhcpPacket->m_iNbrOpt - 1; i++)
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
				{	
					memset(buf + ip_len - padding, 0, padding);
				}

				((SOCKADDR_IN*)&src_sockaddr)->sin_family = ((SOCKADDR_IN*)&dst_sockaddr)->sin_family = AF_INET;
				((SOCKADDR_IN*)&src_sockaddr)->sin_port = myUDPv4hdr->src_port;
				((SOCKADDR_IN*)&src_sockaddr)->sin_addr.s_addr = myIPv4Hdr->ip_srcaddr;

				((SOCKADDR_IN*)&dst_sockaddr)->sin_port = myUDPv4hdr->dst_port;
				((SOCKADDR_IN*)&dst_sockaddr)->sin_addr.s_addr = inet_addr(m_SrvAddrs[j].c_str());

				time(&(DhcpPacket->m_ltime));

				if (sendto(sock, buf, ip_len, 0, (SOCKADDR*)&dst_sockaddr, sizeof(dst_sockaddr)) == SOCKET_ERROR)
				{
					printf("SendDhcpRequest() : ERROR sendto() call %d\n", WSAGetLastError());
				}

				if (m_StateTransition == StateTransition::Releasing)
					goto cleanup;

				//ZeroMemory the buffer
				ZeroMemory(buf, sizeof(char) * DHCP_MAX_PACKET_SIZE);
			}
		}

	cleanup:
		DhcpPacket->m_iRetry++;

		closesocket(sock);
		WSACleanup();

		if (OptBuf != NULL)
			free(OptBuf);

		if (buf != NULL)
			free(buf);

		DEBUG_PRINT("<-- SendDhcpRequest()\n");

		return iResult;
	}


}