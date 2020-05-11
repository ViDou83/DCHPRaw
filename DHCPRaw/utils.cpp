#include "DHCPRaw.h"

typedef struct DATA_WORKER_THREAD {
	int ifIndex;
} DATA_WORKER_THREAD, * PDATA_WORKER_THREAD;


#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

/////////////////////////
//// PACKET HEADERS FUNCTIONS
////////
pIPv4_HDR BuildIPv4Hdr(ULONG SrcIp, ULONG DstIp, USHORT ip_len, USHORT Proto) 
{
	pIPv4_HDR ipv4hdr = (pIPv4_HDR)MALLOC(sizeof(IPv4_HDR));

	ipv4hdr->ip_verlen = (4 << 4) | (sizeof(IPv4_HDR) / sizeof(ULONG));
	ipv4hdr->ip_tos = 0;
	ipv4hdr->ip_totallength = htons(ip_len);
	ipv4hdr->ip_id = 1;
	ipv4hdr->ip_offset = 0;
	ipv4hdr->ip_ttl = 128;					// Time-to-live is eight
	ipv4hdr->ip_protocol = (BYTE)Proto;
	ipv4hdr->ip_checksum = 0;
	ipv4hdr->ip_srcaddr = SrcIp;
	ipv4hdr->ip_destaddr = DstIp;

	return ipv4hdr;
}

pUDPv4_HDR BuildUDPv4Hdr(USHORT SrcPort, USHORT DstPort, USHORT udp_len) 
{
	pUDPv4_HDR udphdr = (pUDPv4_HDR)MALLOC(sizeof(UDPv4_HDR));

	udphdr->src_port = htons(SrcPort);
	udphdr->dst_port = htons(DstPort);
	udphdr->udp_length = htons(udp_len);
	udphdr->udp_checksum = 0;

	return udphdr;
}

/////////////////////////
//// DHCP HELPERS FUNCTIONS
////////
USHORT build_option50_54(USHORT OptionType, ULONG RequestedIP, PDHCP_OPT DhcpOpt)
{

	DhcpOpt->OptionType = (BYTE)OptionType;

	DhcpOpt->OptionLength = 4;
	DhcpOpt->OptionValue = (PBYTE)malloc(sizeof(BYTE) * DhcpOpt->OptionLength + 2);
	//ULONG to BYTE
	DhcpOpt->OptionValue[0] = (BYTE)((RequestedIP & 0xFF000000) >> 24);
	DhcpOpt->OptionValue[1] = (BYTE)((RequestedIP & 0x00FF0000) >> 16);
	DhcpOpt->OptionValue[2] = (BYTE)((RequestedIP & 0x0000FF00) >> 8);
	DhcpOpt->OptionValue[3] = (BYTE)((RequestedIP & 0x000000FF));

	return DhcpOpt->OptionLength + 2;
}

USHORT build_option53(USHORT MsgType, PDHCP_OPT DhcpOpt)
{
	if (MsgType >= 1 && MsgType <= 8)
	{

		DhcpOpt->OptionType = DHCP_MESSAGETYPE;
		DhcpOpt->OptionLength = 1;
		DhcpOpt->OptionValue = (PBYTE)malloc(sizeof(BYTE) * DhcpOpt->OptionLength);
		DhcpOpt->OptionValue[0] = (BYTE)MsgType;
	}
	else
		return EXIT_SUCCESS;

	return DhcpOpt->OptionLength + 1;
}

USHORT build_option_55(BYTE ParameterRequestList[], PDHCP_OPT DhcpOpt)
{
	DhcpOpt->OptionType = DHCP_PARAMREQUEST;
	DhcpOpt->OptionLength = 5;
	DhcpOpt->OptionValue = (PBYTE)malloc(sizeof(BYTE) * DhcpOpt->OptionLength);

	for (int i = 0; i < DhcpOpt->OptionLength; i++)
		DhcpOpt->OptionValue[i] = ParameterRequestList[i];

	return DhcpOpt->OptionLength + 2;
}


/*
* Builds DHCP option61 on dhopt_buff
*/
USHORT build_option_61(PUCHAR MacAddr, PDHCP_OPT DhcpOpt)
{
	DhcpOpt->OptionType = DHCP_CLIENTID;
	DhcpOpt->OptionLength = ETHER_ADDR_LEN + 1;
	DhcpOpt->OptionValue = (PBYTE)malloc(sizeof(BYTE) * DhcpOpt->OptionLength);
	//ULONG to BYTE
	DhcpOpt->OptionValue[0] = DHCP_OPT_HARDWARE_TYPE;
	for (int i = 1; i < DhcpOpt->OptionLength; i++)
		DhcpOpt->OptionValue[i] = MacAddr[i - 1];

	return DhcpOpt->OptionLength + 2;
}

/*
* Builds DHCP option61 on dhopt_buff
*/
USHORT build_dhcp_option(BYTE OptionType, BYTE OptionLength, PBYTE OptionValue, PDHCP_OPT pDhcpOpt)
{

	pDhcpOpt->OptionType = OptionType;
	pDhcpOpt->OptionLength = OptionLength;
	pDhcpOpt->OptionValue = (PBYTE)malloc(sizeof(BYTE) * pDhcpOpt->OptionLength);
	//ULONG to BYTE
	for (int i = 0; i < pDhcpOpt->OptionLength; i++)
		pDhcpOpt->OptionValue[i] = OptionValue[i];

	return pDhcpOpt->OptionLength + 2;
}

/*
* Builds DHCP option81 on dhopt_buff
see https://technet.microsoft.com/en-us/library/cc959284.aspx
*/
USHORT build_option_81(char* FQDN, PDHCP_OPT DhcpOpt)
{
	DhcpOpt->OptionType = DHCP_FQDN;
	DhcpOpt->OptionLength = (BYTE)strlen((const char*)FQDN) + 3;
	DhcpOpt->OptionValue = (PBYTE)malloc(sizeof(BYTE) * DhcpOpt->OptionLength);

	USHORT flags = 0;
	USHORT rcode1 = 0;
	USHORT rcode2 = 0;

	//flags |= FQDN_N_FLAG;

	flags = FQDN_S_FLAG;

	DhcpOpt->OptionValue[0] = (BYTE)flags;
	DhcpOpt->OptionValue[1] = (BYTE)rcode1;
	DhcpOpt->OptionValue[2] = (BYTE)rcode2;

	memcpy(&DhcpOpt->OptionValue[3], FQDN, strlen((const char*)FQDN));
	return DhcpOpt->OptionLength + 2;
}


void DumpDhcpMsg(pDHCPv4_HDR DhcpPacket) 
{
	char dhcp_cip[INET_ADDRSTRLEN];
	char dhcp_yip[INET_ADDRSTRLEN];
	char dhcp_sip[INET_ADDRSTRLEN];
	char dhcp_gip[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &(DhcpPacket->dhcp_cip), dhcp_cip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(DhcpPacket->dhcp_yip), dhcp_yip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(DhcpPacket->dhcp_sip), dhcp_sip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(DhcpPacket->dhcp_gip), dhcp_gip, INET_ADDRSTRLEN);

	if (sizeof(DhcpPacket) != NULL) {
		printf("####################\n");
		printf("# DUMPING DHCP MSG #\n");
		printf("####################\n");
		printf("dhcp_opcode=%d\ndhcp_htype=%d\ndhcp_hlen=%d\ndhcp_hopcount=%d\ndhcp_xid=%.8X\ndhcp_secs=%d\ndhcp_flags=%.4X\n", DhcpPacket->dhcp_opcode, \
			DhcpPacket->dhcp_htype, DhcpPacket->dhcp_hlen, DhcpPacket->dhcp_hopcount, \
			DhcpPacket->dhcp_xid, DhcpPacket->dhcp_secs, DhcpPacket->dhcp_flags);

		printf("dhcp_cip=%s\ndhcp_yip=%s\ndhcp_sip=%s\ndhcp_gip=%s\ndhcp_chaddr=%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\ndhcp_sname=%s\ndhcp_file=%s\ndhcp_magic=%.8X\n", \
			dhcp_cip, dhcp_yip, dhcp_sip, dhcp_gip, DhcpPacket->dhcp_chaddr[0], DhcpPacket->dhcp_chaddr[1], DhcpPacket->dhcp_chaddr[2], \
			DhcpPacket->dhcp_chaddr[3], DhcpPacket->dhcp_chaddr[4], DhcpPacket->dhcp_chaddr[5], \
			DhcpPacket->dhcp_sname, DhcpPacket->dhcp_file, DhcpPacket->dhcp_magic
		);
		printf("####################\n");
	}
}

/////////////////////////
//// IP HELPER FUNCTIONS
////////
DWORD MyEcho(char* strIpAddr)
{
	// Declare and initialize variables
	HANDLE hIcmpFile;
	unsigned long ulIpAddr = INADDR_NONE;
	DWORD dwRetVal = 0;
	char SendData[32] = "Data Buffer";
	LPVOID ReplyBuffer = NULL;
	DWORD ReplySize = 0;

	DEBUG_PRINT("--> MyEcho(): ping %s\n", strIpAddr);
	ulIpAddr= inet_addr(strIpAddr);
	if (ulIpAddr == INADDR_NONE)
	{
		printf("usage: %s IP address\n", strIpAddr);
		return EXIT_FAILURE;
	}

	hIcmpFile = IcmpCreateFile();
	if (hIcmpFile == INVALID_HANDLE_VALUE)
	{
		printf("\tUnable to open handle.\n");
		printf("IcmpCreatefile returned error: %ld\n", GetLastError());
		return EXIT_FAILURE;
	}

	ReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData);
	ReplyBuffer = (VOID*)MALLOC(ReplySize);
	if (ReplyBuffer == NULL)
	{
		printf("\tUnable to allocate memory\n");
		return EXIT_FAILURE;
	}

	dwRetVal = IcmpSendEcho(hIcmpFile, ulIpAddr, SendData, sizeof(SendData),
		NULL, ReplyBuffer, ReplySize, 1000);
	if (dwRetVal != 0) {
		PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)ReplyBuffer;
		struct in_addr ReplyAddr;
		ReplyAddr.S_un.S_addr = pEchoReply->Address;
		DEBUG_PRINT("\tSent icmp message to %s\n", strIpAddr);
		
		DEBUG_PRINT("MyEcho(): Received %ld icmp message response\n", dwRetVal);
		
		DEBUG_PRINT("\tInformation from the first response:\n");
		DEBUG_PRINT("\t  Received from %s\n", inet_ntoa(ReplyAddr));
		DEBUG_PRINT("\t  Status = %ld\n",
			pEchoReply->Status);
		DEBUG_PRINT("\t  Roundtrip time = %ld milliseconds\n",
			pEchoReply->RoundTripTime);
	}
	else
	{
		DEBUG_PRINT("\tCall to IcmpSendEcho failed.\n");
		DEBUG_PRINT("\tIcmpSendEcho returned error: %ld\n", GetLastError());
		return 1;
	}

	FREE(ReplyBuffer);

	return EXIT_SUCCESS;
}

bool IsIPv4AddrPlumbebOnAdapter(int IfIndex, char* IPv4) {

	DEBUG_PRINT("--> IsIPv4AddrPlumbebOnAdapter()\n");

	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL) {
		printf("Error allocating memory needed to call GetAdaptersinfo\n");
		return false;
	}

	// Make an initial call to GetAdaptersInfo to get
	// the necessary size into the ulOutBufLen variable
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		FREE(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
			return false;
		}
	}

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		while (pAdapter)
		{
			if (pAdapter->Index == IfIndex) {
				PIP_ADDR_STRING  pIpAddrString = &pAdapter->IpAddressList;
				do {
					if (strcmp(pIpAddrString->IpAddress.String, IPv4) == 0)
					{
						DEBUG_PRINT("<-- IsIPv4AddrPlumbebOnAdapter() %s Found\n", IPv4);
						return true;
					}
					pIpAddrString = pIpAddrString->Next;
				} while (pIpAddrString != NULL);
			}
			pAdapter = pAdapter->Next;
		}
	}
	DEBUG_PRINT("<-- IsIPv4AddrPlumbebOnAdapter() Not Found\n");

	return false;
}


void CleanupAlternateIPv4OnInt(int IfIndex, char* IPv4) {
	DEBUG_PRINT("--> CleanupAlternateIPv4OnInt()\n");

	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL) {
		printf("Error allocating memory needed to call GetAdaptersinfo\n");
	}

	// Make an initial call to GetAdaptersInfo to get
	// the necessary size into the ulOutBufLen variable
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		FREE(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
		}
	}

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		while (pAdapter) {
			if (pAdapter->Index == IfIndex) {
				PIP_ADDR_STRING  pIpAddrString = &pAdapter->IpAddressList;
				while (pIpAddrString->Next != NULL) {
					pIpAddrString = pIpAddrString->Next;
					DEBUG_PRINT("CleanupAlternateIPv4OnInt(): IPv4 address %s is goint to be deleted \n", pIpAddrString->IpAddress.String);

					if (IPv4 == "All" || strcmp(pIpAddrString->IpAddress.String, IPv4) == 0) {
						if ((dwRetVal = DeleteIPAddress(pIpAddrString->Context) == NO_ERROR))
							DEBUG_PRINT("CleanupAlternateIPv4OnInt(): IPv4 address was successfully deleted.\n");
						else
							DEBUG_PRINT("CleanupAlternateIPv4OnInt(): IPv4 address was not successfully deleted.\n");
					}
				}
			}
			pAdapter = pAdapter->Next;
		}
	}

	DEBUG_PRINT("<-- CleanupAlternateIPv4OnInt()\n");
}

DWORD GetAdapterMacByIndex(int IfIndex, BYTE (&MAC)[ETHER_ADDR_LEN])
{
	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;
	UINT i;

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	////DEBUG_PRINT("--> GetAdaptersMACbyIndex():%d %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", ifIndex, AddrMac[0], AddrMac[1], AddrMac[2], AddrMac[3], AddrMac[4], AddrMac[5]);

	pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL)
	{
		printf("Error allocating memory needed to call GetAdaptersinfo\n");
		return EXIT_FAILURE;
	}
	// Make an initial call to GetAdaptersInfo to get
	// the necessary size into the ulOutBufLen variable
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
	{
		FREE(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
			return EXIT_FAILURE;
		}
	}

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		while (pAdapter) {
			if (pAdapter->Index == IfIndex)
			{
				for (i = 0; i < pAdapter->AddressLength; i++)
					MAC[i] = (int)pAdapter->Address[i];
				break;
			}
			pAdapter = pAdapter->Next;
		}
	}

	if (pAdapterInfo)
		FREE(pAdapterInfo);

	////DEBUG_PRINT("<-- ():%d %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", ifIndex, AddrMac[0], AddrMac[1], AddrMac[2], AddrMac[3], AddrMac[4], AddrMac[5]);

	return EXIT_SUCCESS;
}

/**/
DWORD ListAllAdapters() 
{
	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;
	UINT i;

	/* variables used to print DHCP time info */
	struct tm newtime;
	char buffer[32];
	errno_t error;

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL) 
	{
		printf("Error allocating memory needed to call GetAdaptersinfo\n");
		return EXIT_FAILURE;
	}

	// Make an initial call to GetAdaptersInfo to get
	// the necessary size into the ulOutBufLen variable
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) 
	{
		FREE(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
			return EXIT_FAILURE;
		}
	}

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) 
	{
		pAdapter = pAdapterInfo;
		while (pAdapter) {
			printf("#######\n");
			printf("\tComboIndex: \t%d\n", pAdapter->ComboIndex);
			printf("\tAdapter Name: \t%s\n", pAdapter->AdapterName);
			printf("\tAdapter Desc: \t%s\n", pAdapter->Description);
			printf("\tAdapter Addr: \t");
			for (i = 0; i < pAdapter->AddressLength; i++) {
				if (i == (pAdapter->AddressLength - 1))
					printf("%.2X\n", (int)pAdapter->Address[i]);
				else
					printf("%.2X-", (int)pAdapter->Address[i]);
			}
			printf("\tIndex: \t%d\n", pAdapter->Index);
			printf("\tType: \t");
			switch (pAdapter->Type) {
			case MIB_IF_TYPE_OTHER:
				printf("Other\n");
				break;
			case MIB_IF_TYPE_ETHERNET:
				printf("Ethernet\n");
				break;
			case MIB_IF_TYPE_TOKENRING:
				printf("Token Ring\n");
				break;
			case MIB_IF_TYPE_FDDI:
				printf("FDDI\n");
				break;
			case MIB_IF_TYPE_PPP:
				printf("PPP\n");
				break;
			case MIB_IF_TYPE_LOOPBACK:
				printf("Lookback\n");
				break;
			case MIB_IF_TYPE_SLIP:
				printf("Slip\n");
				break;
			default:
				printf("Unknown type %ld\n", pAdapter->Type);
				break;
			}

			PIP_ADDR_STRING  pIpAddrString = &pAdapter->IpAddressList;
			do {
				printf("\tIP Address: \t%s\n",
					pIpAddrString->IpAddress.String);
				printf("\tIP Mask: \t%s\n", pIpAddrString->IpMask.String);
				pIpAddrString = pIpAddrString->Next;
			} while (pIpAddrString != NULL);

			printf("\tGateway: \t%s\n", pAdapter->GatewayList.IpAddress.String);
			printf("\t***\n");

			if (pAdapter->DhcpEnabled) 
			{
				printf("\tDHCP Enabled: Yes\n");
				printf("\t  DHCP Server: \t%s\n",
					pAdapter->DhcpServer.IpAddress.String);

				printf("\t  Lease Obtained: ");
				/* Display local time */
				error = _localtime32_s(&newtime, (__time32_t*)&pAdapter->LeaseObtained);
				if (error)
					printf("Invalid Argument to _localtime32_s\n");
				else 
				{
					// Convert to an ASCII representation 
					error = asctime_s(buffer, 32, &newtime);
					if (error)
						printf("Invalid Argument to asctime_s\n");
					else
						/* asctime_s returns the string terminated by \n\0 */
						printf("%s", buffer);
				}

				printf("\t  Lease Expires:  ");
				error = _localtime32_s(&newtime, (__time32_t*)&pAdapter->LeaseExpires);
				if (error)
					printf("Invalid Argument to _localtime32_s\n");
				else {
					// Convert to an ASCII representation 
					error = asctime_s(buffer, 32, &newtime);
					if (error)
						printf("Invalid Argument to asctime_s\n");
					else
						/* asctime_s returns the string terminated by \n\0 */
						printf("%s", buffer);
				}
			}
			else
				printf("\tDHCP Enabled: No\n");

			if (pAdapter->HaveWins) {
				printf("\tHave Wins: Yes\n");
				printf("\t  Primary Wins Server:    %s\n",
					pAdapter->PrimaryWinsServer.IpAddress.String);
				printf("\t  Secondary Wins Server:  %s\n",
					pAdapter->SecondaryWinsServer.IpAddress.String);
			}
			else
				printf("\tHave Wins: No\n");
			pAdapter = pAdapter->Next;
			printf("\n");
		}
	}
	else 
	{
		printf("GetAdaptersInfo failed with error: %d\n", dwRetVal);
	}
	if (pAdapterInfo)
		FREE(pAdapterInfo);

	return EXIT_SUCCESS;
}

LARGE_INTEGER UnixTimeToFileTime(time_t time)
{
	LARGE_INTEGER n;
	n.QuadPart = (time + 11644473600ULL) * 10000000ULL;
	return n;
}
