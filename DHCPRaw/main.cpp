// DHCPRaw.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include "DHCPRaw.h"

#define PROGRAM_MAJOR_VERSION 1
#define PROGRAM_MINOR_VERSION 0

#define NBR_WORKER_THREADS 2
#define NBR_DHCP_SENDER 1
#define NBR_DHCP_RECEIVERS 1


CRITICAL_SECTION g_CS[DHCP_REPLY];
HANDLE g_hSocketWaitEvent;
HANDLE g_hDiscoverReadyWaitEvent;
bool g_DhcpReceiverAlone = false;

using namespace DHCPRaw;

/* Helper */
void Help() 
{
	cout << "DhcpRaw:" << endl;
	cout << "Version: " << PROGRAM_MAJOR_VERSION << "." << PROGRAM_MINOR_VERSION << endl;
	cout << "Author: Vincent Douhet <vidou@microsoft.com>" << endl;;
	cout << "----------------------------------------------------------------" << endl;
	cout << "Usage:\tregular mode:\tDhcpRaw -i {ifIndex} -n {NbrLeasesWanted} -a" << endl;
	cout << "\tRelay mode:\tDhcpRaw -i {ifIndex} -n {NbrLeasesWanted} -r  {AddrIP} -s {AddrIP} -a" << endl;
	cout << "----------------------------------------------------------------" << endl;
	cout << "\t-i: Specify the ifIndex of the NIC where you want to send out DHCP msg (please run DHCPRaw.exe -d" << endl;;
	cout << "\t-n: Number of DHCP leases you want to request" << endl;
	cout << "\t-r: RELAY MODE ONLY: Address ip to borrow as DHCP relay. Alternate IP Address will be plumbed on the NIC specified by -i" << endl;
	cout << "\t-s: RELAY MODE ONLY: Specify the ip address of the DHCP server to which relay (for fake) the DHCP messages. To allow the DHCP SRV to respond, please add a default route to this machine or a arp static entry" << endl;
	cout << "\t-d: Dump all local system's adapters settings and attributes" << endl;
	cout << "\t-a: Automatically send DHCP release for granted lease(s)" << endl;
	cout << "\t-f: Specify a .INI files containing instruction : support of custom DHCP options" << endl;
}

int main(int argc, char* argv[])
{
	int IfIndex = 0;
	int NbrLeases = 1;
	char* RelayAddr = NULL;
	char* SrvAddr = NULL;
	bool bIsRealyOn = false;

	/* Variables where handles to the added IP are returned */
	ULONG NTEContext = 0;
	ULONG NTEInstance = 0;
	DWORD dwRetVal = 0;


	/* Checking args number */
	if (argc < 2)
	{
		Help();
		return EXIT_SUCCESS;
	}

	/* Checking is we are on server SKU
	if (!IsWindowsServer())
	{
		cout << "###############################################################################################################" << endl;
		cout << "#\t\t\t\t\t\t\t\t\t\t\t\t\t\t#" << endl;
		cout << "#\tPlease note that this binary is only working on WindowsServer as RAW socket capability is needed !\t#" << endl;
		cout << "#\t\t\t\t\t\t\t\t\t\t\t\t\t\t#" << endl;
		cout << "#\t https://docs.microsoft.com/en-us/windows/desktop/winsock/tcp-ip-raw-sockets-2 \t\t\t\t#" << endl;
		cout << "#\t\t\t\t\t\t\t\t\t\t\t\t\t\t#" << endl;
		cout << "#\tTo use a socket of type SOCK_RAW requires administrative privileges.\t\t\t\t\t#" << endl;
		cout << "#\tUsers running Winsock applications that use raw sockets must be a member of the Administrators\t\t#" << endl;
		cout << "#\tgroup on the local computer, otherwise raw socket calls will fail with an error code of WSAEACCES.\t#" << endl;
		cout << "#\tOn Windows Vista and later, access for raw sockets is enforced at socket creation.\t\t\t#" << endl;
		cout << "#\tIn earlier versions of Windows, access for raw sockets is enforced during other socket operations.\t#" << endl;
		cout << "#\t\t\t\t\t\t\t\t\t\t\t\t\t\t#" << endl;
		cout << "###############################################################################################################" << endl;

		Help();

		return EXIT_SUCCESS;
	}
	*/

	for (int i = 0; i < argc; i++)
	{
		if (strcmp(argv[i], "-i") == 0)
			IfIndex = atoi(argv[i + 1]);
		else if (strcmp(argv[i], "-n") == 0)
			NbrLeases = atoi(argv[i + 1]);
		else if (strcmp(argv[i], "-r") == 0)
		{
			bIsRealyOn = true;
			RelayAddr = argv[i + 1];
		}
		else if (strcmp(argv[i], "-s") == 0)
		{
			bIsRealyOn = true;
			SrvAddr = argv[i + 1];
		}
	}

	//Exit if no TCPIP adapter has been provided
	if (!IfIndex) {
		printf("----------------------------------------------------------------\n");
		printf("Error: Please specify one interface Index where to send out DHCP messages\n");
		printf("----------------------------------------------------------------\n\n");
		Help();
		printf("----------------------------------------------------------------\n");
		//GetAdaptersInfo();
		return EXIT_FAILURE;
	}

	//Adding Ip Address of Relay
	if (bIsRealyOn)
	{
		if (!IsIPv4AddrPlumbebOnAdapter(IfIndex, RelayAddr))
		{
			if (dwRetVal = AddIPAddress(inet_addr(RelayAddr), inet_addr("255.255.255.0"), IfIndex, &NTEContext, &NTEInstance) == NO_ERROR)
				printf("main(): Relay IPv4 address %s was successfully added.\n", RelayAddr);
			else
				printf("main(): IPv4 address %s failed to be added with error: %d\n", RelayAddr, dwRetVal);

			//Waiting till the IP is bound
			do
			{
				printf("main(): waiting till RelayAddr=%s is reachabled\n", RelayAddr);
				Sleep(5000);
			} while (MyEcho(RelayAddr) != 0);

		}
	}

	/*	Initialize THREADS :
		1) One for dealing with receive DHCP packets
		2) Multiple sender aka DHCP CLients
		Create a SocketWaitEvent event object. Thread 1) will set it when start to receive (in listening state)
		Thread(s) 2) will wait on SocketWaitEvent before starting
	*/
	g_hSocketWaitEvent = CreateEvent(
		NULL,               // default security attributes
		TRUE,               // manual-reset event
		FALSE,              // initial state is nonsignaled
		TEXT("SocketWaitEvent")  // object name
	);

	if (g_hSocketWaitEvent == NULL)
	{
		printf("SocketWaitEvent creation failed (%d)\n", GetLastError());
		return EXIT_FAILURE;
	}

	g_hDiscoverReadyWaitEvent = CreateEvent(
		NULL,               // default security attributes
		TRUE,               // manual-reset event
		FALSE,              // initial state is nonsignaled
		TEXT("DiscoverReadyWaitEvent")  // object name
	);

	if (g_hDiscoverReadyWaitEvent == NULL)
	{
		printf("DiscoverReadyWaitEvent failed (%d)\n", GetLastError());
		return EXIT_FAILURE;
	}

	/* Initialize Mutex by DHCP type Q
		TODO : change MUTEX by CriticalSection
	*/
	for (int i = 0; i < DHCP_REPLY; i++)
	{
		if (!InitializeCriticalSectionAndSpinCount(&g_CS[i], 0x00000400))
			return EXIT_FAILURE;
	}
		

	//Init Threads DATAs : Last thread is the sender
	PHANDLE hWorkerThread = (PHANDLE)malloc(sizeof(HANDLE) * ((unsigned long long)NbrLeases + 1));
	/* Sender Thread Init:
	This/those (only one currently) thread(s) will send DHCP Request/messages out on the wire
		ThreadStartupRoutine : DhcpClient / See functions.cpp
	*/

	/* Getting MAC from ifIndex using IPHELPER API*/
	//print client number
	DHCPRawClient* DHCPClients = new DHCPRawClient[NbrLeases + 1];  // Array of size n of Matrix-objects  


	bool IsReceiver = true;
	DHCPClients[NbrLeases] = DHCPRawClient(NbrLeases, IsReceiver, bIsRealyOn);
	hWorkerThread[NbrLeases] = DHCPClients[NbrLeases].Run();

	IsReceiver = false;
	for (int i = 0; i < NbrLeases; i++)
	{
		if(bIsRealyOn)
			DHCPClients[i] = DHCPRawClient(i, IfIndex,(char*)"DHCPRAW", bIsRealyOn,RelayAddr,SrvAddr);
		else
			DHCPClients[i] = DHCPRawClient(i, IfIndex, (char*)"DHCPRAW");
		hWorkerThread[i] = DHCPClients[i].Run();
	}

	
	// Waiting on DHCP CLient thread to terminate before exiting program
	WaitForMultipleObjects(NbrLeases, hWorkerThread, TRUE, INFINITE);

	// Waiting on DHCP Receiver thread to stop
	g_DhcpReceiverAlone = true;
	WaitForMultipleObjects(1, hWorkerThread, TRUE, INFINITE);

	printf("DHCPRaw is exiting. Thanks for using it! Feedback : vidou@microsoft.com / vincent.douhet@gmail.com\n");

	return EXIT_SUCCESS;
}


