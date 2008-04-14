// ========================================================================================================================
// Scamp
//
// Copyright ©2007-2008 Liam Kirton <liam@int3.ws>
// ========================================================================================================================
// Scamp.cpp
//
// Created: 16/03/2007
// ========================================================================================================================

#include <winsock2.h>
#include <windows.h>

#include <iphlpapi.h>
#include <wincrypt.h>

#include <algorithm>
#include <cmath>
#include <exception>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <queue>
#include <sstream>
#include <string>
#include <vector>

#include <pcap.h>

#include "Scamp.h"

// ========================================================================================================================

BOOL WINAPI ConsoleCtrlHandlerRoutine(DWORD dwCtrlType);

DWORD WINAPI PcapListenThreadProc(LPVOID lpParameter);
void OnListenArp(pcap_pkthdr *pPktHeader, const u_char *pPktData);
void OnListenIpIcmp(pcap_pkthdr *pPktHeader, const u_char *pPktData);
void OnListenIpTcp(pcap_pkthdr *pPktHeader, const u_char *pPktData);

DWORD WINAPI PcapScanThreadProc(LPVOID lpParameter);
DWORD WINAPI ResolveThreadProc(LPVOID lpParameter);

void GenerateScanStructs(std::string &targetString);
void PrintResults(std::ostream &stream, std::ifstream &inOui);
void PrintResultsIcmpType(std::ostream &stream, std::vector<IcmpEventStruct> &responses);
void PrintResultsTraceType(std::ostream &stream, std::vector<IcmpEventStruct> &responses);

void PrintResultsHostName(std::ostream &stream, const u_int ip);
void PrintResultsMacVendor(std::ostream &stream, std::ifstream &inOui, const u_char *mac);

void PrintUsage();

// ========================================================================================================================

const char *g_cScampVersion = "0.3.4";

// ========================================================================================================================

CRITICAL_SECTION g_ConsoleCriticalSection;
HANDLE g_hExitEvent = NULL;
HANDLE g_hPcapListenThread = NULL;
HANDLE g_hPcapScanThread = NULL;
HANDLE g_hResolveThread = NULL;
HCRYPTPROV g_hCryptProv = NULL;

LARGE_INTEGER g_lCounterFrequency;

pcap_if_t *g_pDevice = NULL;
pcap_t *g_pAdapter = NULL;
PIP_ADAPTER_INFO g_pAdapterInfo = NULL;

u_short g_ScanType = 0x0000;
std::map<u_int, ScanStruct *> g_ScanStructs;

bool g_bResolveHosts = false;
HANDLE g_hHostNamesMutex = NULL;
std::map<u_int, std::string> g_HostNames;

u_short g_DestinationPort = 0;
u_short g_SourcePort = 0;

bool g_bNonAdapterIp = false;
u_int g_SourceIp = 0x00000000;
u_int g_SourceNetMask = 0x00000000;
u_int g_DefaultRouteIp = 0x00000000;
ScanStruct *g_DefaultRouteScanStruct = NULL;

u_int g_uPacketAttemptCount = 3;
u_int g_uPacketBlockCount = 1;
u_int g_uPacketIntervalMs = 100;
u_int g_uPacketQueueCount = 32;
u_int g_uWaitEndMs = 2500;
LARGE_INTEGER g_lCounterLastActivity;

u_short g_IpIdentification;

// ========================================================================================================================

int main(int argc, char *argv[])
{
	std::cout << std::endl
			  << "Scamp " << g_cScampVersion << std::endl
			  << "Copyright " << "\xB8" << "2007-2008 Liam Kirton <liam@int3.ws>" << std::endl
			  << std::endl
			  << "Built at " << __TIME__ << " on " << __DATE__ << std::endl << std::endl;

	WSADATA wsaData;
	if(WSAStartup(0x0202, &wsaData) != 0)
	{
		std::cout << "Error: WSAStartup(2.2) Failed." << std::endl << std::endl;
		return -1;
	}

	u_int uDeviceId = 0xFFFFFFFF;
	std::string outputFileName;
	std::string targetString;

	if(timeBeginPeriod(1) != TIMERR_NOERROR)
	{
		std::cout << "WARNING: timeBeginPeriod(1) Failed." << std::endl << std::endl;
	}
	QueryPerformanceFrequency(&g_lCounterFrequency);

	if(!CryptAcquireContext(&g_hCryptProv, NULL, NULL, PROV_RSA_FULL, 0))
	{
		if(!CryptAcquireContext(&g_hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET))
		{
			std::cout << "CryptAcquireContext() Failed." << std::endl << std::endl;
			return -1;
		}
	}

	if(!CryptGenRandom(g_hCryptProv, 2, reinterpret_cast<BYTE *>(&g_SourcePort)))
	{
		std::cout << "CryptGenRandom() Failed." << std::endl << std::endl;
		return -1;
	}
	if(!CryptGenRandom(g_hCryptProv, 2, reinterpret_cast<BYTE *>(&g_DestinationPort)))
	{
		std::cout << "CryptGenRandom() Failed." << std::endl << std::endl;
		return -1;
	}
	if(!CryptGenRandom(g_hCryptProv, 2, reinterpret_cast<BYTE *>(&g_IpIdentification)))
	{
		std::cout << "CryptGenRandom() Failed." << std::endl << std::endl;
		return -1;
	}

	try
	{
		for(int i = 1; i < argc; ++i)
		{
			std::string cmd = argv[i];
			std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);

			if((cmd == "/device") && ((i + 1) < argc))
			{
				uDeviceId = static_cast<u_int>(strtol(argv[++i], NULL, 10));
			}
			else if((cmd == "/target") && ((i + 1) < argc))
			{
				targetString = argv[++i];
			}
			else if((cmd == "/ip") && ((i + 1) < argc))
			{
				g_SourceIp = inet_addr(argv[++i]);
			}
			else if((cmd == "/netmask") && ((i + 1) < argc))
			{
				g_SourceNetMask = inet_addr(argv[++i]);
			}
			else if((cmd == "/route") && ((i + 1) < argc))
			{
				g_DefaultRouteIp = inet_addr(argv[++i]);
			}
			else if((cmd == "/interval") && ((i + 1) < argc))
			{
				g_uPacketIntervalMs = static_cast<u_int>(strtol(argv[++i], NULL, 10));
			}
			else if((cmd == "/block") && ((i + 1) < argc))
			{
				g_uPacketBlockCount = static_cast<u_int>(strtol(argv[++i], NULL, 10));
			}
			else if((cmd == "/queue") && ((i + 1) < argc))
			{
				g_uPacketQueueCount = static_cast<u_int>(strtol(argv[++i], NULL, 10));
			}
			else if((cmd == "/retry") && ((i + 1) < argc))
			{
				g_uPacketAttemptCount = static_cast<u_int>(strtol(argv[++i], NULL, 10)) + 1;
			}
			else if((cmd == "/trace") && ((i + 1) < argc))
			{
				std::string parseRouteType = argv[++i];
				
				std::vector<std::string> routeBlocks;
				u_int routeBlockMarker = 0;
				while(!parseRouteType.empty() && (routeBlockMarker != std::string::npos))
				{
					u_int nextRouteBlockMarker = parseRouteType.find(',', routeBlockMarker + 1);
					std::string routeBlock = parseRouteType.substr(routeBlockMarker + ((routeBlockMarker == 0) ? 0 : 1), nextRouteBlockMarker - routeBlockMarker - ((routeBlockMarker == 0) ? 0 : 1));
					routeBlockMarker = nextRouteBlockMarker;
					routeBlocks.push_back(routeBlock);
				}

				for(std::vector<std::string>::iterator i = routeBlocks.begin(); i != routeBlocks.end(); ++i)
				{
					std::string routeType = (*i);
					std::transform(routeType.begin(), routeType.end(), routeType.begin(), ::tolower);
					routeType = routeType.substr(routeType.find_first_not_of(" \t\r\n"));
					routeType = routeType.substr(0, routeType.find_last_not_of(" \t\r\n") + 1);
					
					if(routeType.empty())
					{
						continue;
					}
					else if(routeType == "e")
					{
						g_ScanType |= ScanTypeIcmpTrace;
					}
					else if(routeType == "t")
					{
						g_ScanType |= ScanTypeTcpTrace;
					}
					else if(routeType == "u")
					{
						g_ScanType |= ScanTypeUdpTrace;
					}
					else
					{
						throw std::exception("Unknown /Route Scan Type Specified.");
					}
				}
			}
			else if((cmd == "/icmp") && ((i + 1) < argc))
			{
				std::string parseIcmpType = argv[++i];
				
				std::vector<std::string> icmpBlocks;
				u_int icmpBlockMarker = 0;
				while(!parseIcmpType.empty() && (icmpBlockMarker != std::string::npos))
				{
					u_int nextIcmpBlockMarker = parseIcmpType.find(',', icmpBlockMarker + 1);
					std::string icmpBlock = parseIcmpType.substr(icmpBlockMarker + ((icmpBlockMarker == 0) ? 0 : 1), nextIcmpBlockMarker - icmpBlockMarker - ((icmpBlockMarker == 0) ? 0 : 1));
					icmpBlockMarker = nextIcmpBlockMarker;
					icmpBlocks.push_back(icmpBlock);
				}

				for(std::vector<std::string>::iterator i = icmpBlocks.begin(); i != icmpBlocks.end(); ++i)
				{
					std::string icmpType = (*i);
					std::transform(icmpType.begin(), icmpType.end(), icmpType.begin(), ::tolower);
					icmpType = icmpType.substr(icmpType.find_first_not_of(" \t\r\n"));
					icmpType = icmpType.substr(0, icmpType.find_last_not_of(" \t\r\n") + 1);
					
					if(icmpType.empty())
					{
						continue;
					}
					else if(icmpType == "e")
					{
						g_ScanType |= ScanTypeIcmpEcho;
					}
					else if(icmpType == "r")
					{
						g_ScanType |= ScanTypeIcmpRouter;
					}
					else if(icmpType == "t")
					{
						g_ScanType |= ScanTypeIcmpTimestamp;
					}
					else if(icmpType == "i")
					{
						g_ScanType |= ScanTypeIcmpInformation;
					}
					else if(icmpType == "n")
					{
						g_ScanType |= ScanTypeIcmpNetmask;
					}
					else
					{
						throw std::exception("Unknown /Icmp Scan Type Specified.");
					}
				}
			}
			else if((cmd == "/dport") && ((i + 1) < argc))
			{
				if(!(g_ScanType & ScanTypeTraceSport))
				{
					g_ScanType |= ScanTypeTraceDport;
				}
				g_DestinationPort = htons(static_cast<u_short>(strtol(argv[++i], NULL, 10)));
			}
			else if((cmd == "/sport") && ((i + 1) < argc))
			{
				if(!(g_ScanType & ScanTypeTraceDport))
				{
					g_ScanType |= ScanTypeTraceSport;
				}
				g_SourcePort = htons(static_cast<u_short>(strtol(argv[++i], NULL, 10)));
			}
			else if(cmd == "/dummy")
			{
				g_ScanType |= ScanTypeDummy;
			}
			else if((cmd == "/output") && ((i + 1) < argc))
			{
				outputFileName = argv[++i];
			}
			else if(cmd == "/verbose")
			{
				g_ScanType |= ScanTypeVerbose;
			}
			else if(cmd == "/resolve")
			{
				g_bResolveHosts = true;
			}
			else
			{
				throw std::exception("Unknown Command.");
			}
		}

		u_int minPacketBlockCount = 0;
		for(u_int i = 4; i < 32; ++i)
		{
			if(g_ScanType & (1 << i))
			{
				minPacketBlockCount++;
			}
		}
		if(minPacketBlockCount == 0)
		{
			minPacketBlockCount = 1;
		}
		if((g_uPacketBlockCount % minPacketBlockCount) != 0)
		{
			g_uPacketBlockCount = minPacketBlockCount;
		}
		if((g_uPacketQueueCount % g_uPacketBlockCount) != 0)
		{
			g_uPacketQueueCount += (g_uPacketQueueCount % g_uPacketBlockCount);
		}
		if(g_uWaitEndMs < (g_uPacketIntervalMs * 2))
		{
			g_uWaitEndMs = g_uPacketIntervalMs * 2;
		}

		if(!((g_ScanType & ScanTypeTraceDport) || (g_ScanType & ScanTypeTraceSport)))
		{
			g_ScanType |= ScanTypeTraceSport;
			g_SourcePort = htons(53);
			g_DestinationPort = htons(33434);			
		}
		else if((g_ScanType & ScanTypeTraceDport) && (g_ScanType & ScanTypeTraceSport))
		{
			throw std::exception("Specify Either /Sport Or /Dport, Not Both.");
		}
		
		if((uDeviceId == 0xFFFFFFFF) || (targetString == ""))
		{
			throw std::exception("Required Parameter Not Specified.");
		}
		else if(!(g_ScanType & ScanTypeIcmpTrace) &&
				!(g_ScanType & ScanTypeUdpTrace) &&
				!(g_ScanType & ScanTypeTcpTrace) &&
				!(g_ScanType & ScanTypeIcmpEcho) &&
				!(g_ScanType & ScanTypeIcmpRouter) &&
				!(g_ScanType & ScanTypeIcmpTimestamp) &&
				!(g_ScanType & ScanTypeIcmpInformation) &&
				!(g_ScanType & ScanTypeIcmpNetmask))
		{
			throw std::exception("No Scan Type Specified.");
		}
	}
	catch(const std::exception &e)
	{
		PrintUsage();
		std::cout << "Error: " << e.what() << std::endl;
		return -1;
	}

	std::cout << "Scanning ICMP: "
			  << ((g_ScanType & ScanTypeIcmpEcho) ? "Echo " : "")
			  << ((g_ScanType & ScanTypeIcmpRouter) ? "Router " : "")
			  << ((g_ScanType & ScanTypeIcmpTimestamp) ? "Time " : "")
			  << ((g_ScanType & ScanTypeIcmpInformation) ? "Info " : "")
			  << ((g_ScanType & ScanTypeIcmpNetmask) ? "Netmask " : "")
			  << "; Traceroute: "
			  << ((g_ScanType & ScanTypeIcmpTrace) ? "ICMP " : "")
			  << ((g_ScanType & ScanTypeUdpTrace) ? "UDP " : "")
			  << ((g_ScanType & ScanTypeTcpTrace) ? "TCP " : "")
			  << "; Ports: ";
	if(g_ScanType & ScanTypeTraceDport)
	{
		std::cout << ntohs(g_SourcePort) << "+ -> " << ntohs(g_DestinationPort);
	}
	else if(g_ScanType & ScanTypeTraceSport)
	{
		std::cout << ntohs(g_SourcePort) << " -> " << ntohs(g_DestinationPort) << "+";
	}
	std::cout << std::endl << std::endl;

	char pcapErrorBuffer[PCAP_ERRBUF_SIZE];
	pcap_if_t *pDeviceList = NULL;
	pcap_if_t *pDeviceEnum = NULL;
	PIP_ADAPTER_INFO pAdapterInfo = NULL;

	InitializeCriticalSection(&g_ConsoleCriticalSection);
	SetConsoleCtrlHandler(ConsoleCtrlHandlerRoutine, TRUE);

	try
	{
		if((g_hExitEvent = CreateEvent(NULL, TRUE, FALSE, NULL)) == NULL)
		{
			throw std::exception("CreateEvent() Failed.");
		}

		if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &pDeviceList, pcapErrorBuffer) == -1)
		{
			throw std::exception("pcap_findalldevs_ex() Failed.");
		}

		u_int uDeviceEnum = 0;
		pDeviceEnum = pDeviceList;
		while(pDeviceEnum != NULL)
		{
			if(++uDeviceEnum == uDeviceId)
			{
				g_pDevice = pDeviceEnum;

				std::string targetDeviceName = g_pDevice->name;
				size_t npfOffset = targetDeviceName.find("NPF_");
				if(npfOffset == std::string::npos)
				{
					throw std::exception("Device Name Format Not Recognised.");
				}
				targetDeviceName = targetDeviceName.substr(npfOffset + 4);

				u_int uBufferSize = 0;
				if(GetAdaptersInfo(pAdapterInfo, reinterpret_cast<PULONG>(&uBufferSize)) == ERROR_BUFFER_OVERFLOW)
				{
					pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(new char[uBufferSize]);
					if(GetAdaptersInfo(pAdapterInfo, reinterpret_cast<PULONG>(&uBufferSize)) != ERROR_SUCCESS)
					{
						throw std::exception("GetAdaptersAddresses(pAdapterInfo) Failed.");
					}

					PIP_ADAPTER_INFO pAdapterInfoEnum = pAdapterInfo;
					do
					{
						if(targetDeviceName.compare(pAdapterInfoEnum->AdapterName) == 0)
						{
							g_pAdapterInfo = pAdapterInfoEnum;
							break;
						}
					}
					while(pAdapterInfoEnum = pAdapterInfoEnum->Next);

					if(pAdapterInfoEnum == NULL)
					{
						throw std::exception("Unable to Match Winpcap Device To Windows Device.");
					}
				}
				break;
			}
			pDeviceEnum = pDeviceEnum->next;
		}
		if((pDeviceEnum == NULL) || (g_pDevice == NULL) || (g_pAdapterInfo == NULL))
		{
			throw std::exception("Winpcap Device Not Found.");
		}

		if((g_SourceIp == 0x00000000) || (g_SourceNetMask == 0x00000000))
		{
			g_SourceIp = inet_addr(g_pAdapterInfo->IpAddressList.IpAddress.String);
			g_SourceNetMask = inet_addr(g_pAdapterInfo->IpAddressList.IpMask.String);
			if(g_DefaultRouteIp == 0x00000000)
			{
				g_DefaultRouteIp = inet_addr(g_pAdapterInfo->GatewayList.IpAddress.String);	
			}

			if(g_SourceIp == g_DefaultRouteIp)
			{
				throw std::exception("Default Route Ip Equal To Source Ip.");
			}
		}
		else if(g_SourceIp != inet_addr(g_pAdapterInfo->IpAddressList.IpAddress.String))
		{
			g_bNonAdapterIp = true;
		}

		GenerateScanStructs(targetString);

		if((g_pAdapter = pcap_open(g_pDevice->name,
								   65535,
								   0,
								   1,
								   NULL,
								   pcapErrorBuffer)) == NULL)
		{
			throw std::exception("pcap_open() Failed.");
		}

		if((g_hPcapListenThread = CreateThread(NULL, 0, PcapListenThreadProc, NULL, 0, NULL)) == NULL)
		{
			throw std::exception("CreateThread() Failed.");
		}
		if((g_hPcapScanThread = CreateThread(NULL, 0, PcapScanThreadProc, NULL, 0, NULL)) == NULL)
		{
			throw std::exception("CreateThread() Failed.");
		}

		if((g_hHostNamesMutex = CreateMutex(NULL, FALSE, NULL)) == NULL)
		{
			throw std::exception("CreateMutex() Failed.");
		}
		if((g_hResolveThread = CreateThread(NULL, 0, ResolveThreadProc, NULL, 0, NULL)) == NULL)
		{
			throw std::exception("CreateThread() Failed.");
		}

		EnterCriticalSection(&g_ConsoleCriticalSection);
		std::cout << "Running. Press Ctrl+C to Abort." << std::endl << std::endl;
		LeaveCriticalSection(&g_ConsoleCriticalSection);
	}
	catch(const std::exception &e)
	{
		EnterCriticalSection(&g_ConsoleCriticalSection);
		if(e.what()[0] != '\0')
		{
			std::cout << std::endl << "Error: " << e.what() << std::endl << std::endl;
		}
		LeaveCriticalSection(&g_ConsoleCriticalSection);
	}

	if(g_hPcapScanThread != NULL)
	{
		if(WaitForSingleObject(g_hPcapScanThread, INFINITE) != WAIT_OBJECT_0)
		{
			EnterCriticalSection(&g_ConsoleCriticalSection);
			std::cout << std::endl << "Warning: WaitForSingleObject() Failed." << std::endl << std::endl;
			LeaveCriticalSection(&g_ConsoleCriticalSection);
		}
		CloseHandle(g_hPcapScanThread);
		g_hPcapScanThread = NULL;

	}

	if(g_hExitEvent != NULL)
	{
		SetEvent(g_hExitEvent);
	}

	if(g_hPcapListenThread != NULL)
	{
		if(WaitForSingleObject(g_hPcapListenThread, INFINITE) != WAIT_OBJECT_0)
		{
			EnterCriticalSection(&g_ConsoleCriticalSection);
			std::cout << std::endl << "Warning: WaitForSingleObject() Failed." << std::endl << std::endl;
			LeaveCriticalSection(&g_ConsoleCriticalSection);
		}
		CloseHandle(g_hPcapListenThread);
		g_hPcapListenThread = NULL;
	}
	if(g_hResolveThread != NULL)
	{
		if(WaitForSingleObject(g_hResolveThread, INFINITE) != WAIT_OBJECT_0)
		{
			EnterCriticalSection(&g_ConsoleCriticalSection);
			std::cout << std::endl << "Warning: WaitForSingleObject() Failed." << std::endl << std::endl;
			LeaveCriticalSection(&g_ConsoleCriticalSection);
		}
		CloseHandle(g_hResolveThread);
		g_hResolveThread = NULL;
	}
	if(g_hHostNamesMutex != NULL)
	{
		CloseHandle(g_hHostNamesMutex);
		g_hHostNamesMutex = NULL;
	}

	if(!g_ScanStructs.empty())
	{
		if(!(g_ScanType & ScanTypeDummy))
		{
			char modulePath[1024];
			DWORD dwModulePathCount = 0;
			if((dwModulePathCount = GetModuleFileName(NULL, modulePath, sizeof(modulePath))) == 0)
			{
				throw std::exception("GetModuleFileName() Failed.");
			}

			for(DWORD i = dwModulePathCount; i >= 0; --i)
			{
				if(modulePath[i] == '\\')
				{
					modulePath[i + 1] = '\0';
					break;
				}
			}
			
			std::string ouiDat = modulePath;
			ouiDat += "Oui.dat";

			std::ifstream inOui(ouiDat.c_str(), std::ios::in);
			std::stringstream resultsStream;
			PrintResults(resultsStream, inOui);
			inOui.close();

			std::cout << std::endl
					  << "Results: " << std::endl
					  << std::endl
					  << resultsStream.str();

			std::ofstream outputFile(outputFileName.c_str(), std::ios::out | std::ios::trunc);
			if(!outputFile.is_open())
			{
				std::exception("Could Not Open Specified Output File.");
			}
			else
			{
				outputFile << std::endl
						   << "Scamp " << g_cScampVersion << std::endl
						   << "Copyright (C)2007-2008 Liam Kirton <liam@int3.ws>" << std::endl
						   << std::endl
						   << "Built at " << __TIME__ << " on " << __DATE__ << std::endl
						   << std::endl
						   << resultsStream.str();
				outputFile.flush();
				outputFile.close();
			}
		}

		for(std::map<u_int, ScanStruct *>::iterator i = g_ScanStructs.begin(); i != g_ScanStructs.end(); ++i)
		{		
			if(i->second->hMutex != NULL)
			{
				CloseHandle(i->second->hMutex);
				i->second->hMutex = NULL;
				delete i->second;
			}
		}

		g_ScanStructs.clear();
	}
	
	if(pDeviceList != NULL)
	{
		pcap_freealldevs(pDeviceList);
		pDeviceList = NULL;
		pDeviceEnum = NULL;
		g_pDevice = NULL;
	}
	if(g_pAdapter != NULL)
	{
		pcap_close(g_pAdapter);
		g_pAdapter = NULL;
	}
	if(pAdapterInfo != NULL)
	{
		delete [] pAdapterInfo;
		pAdapterInfo = NULL;
	}
	
	if(g_hCryptProv != NULL)
	{
		CryptReleaseContext(g_hCryptProv, 0);
		g_hCryptProv = NULL;
	}
	if(g_hExitEvent != NULL)
	{
		CloseHandle(g_hExitEvent);
		g_hExitEvent = NULL;
	}

	SetConsoleCtrlHandler(ConsoleCtrlHandlerRoutine, FALSE);
	DeleteCriticalSection(&g_ConsoleCriticalSection);

	if(timeEndPeriod(1) != TIMERR_NOERROR)
	{
		std::cout << "WARNING: timeEndPeriod(1) Failed." << std::endl << std::endl;
	}

	WSACleanup();

	return 0;
}

// ========================================================================================================================

BOOL WINAPI ConsoleCtrlHandlerRoutine(DWORD dwCtrlType)
{
	if(g_hExitEvent != NULL)
	{
		SetEvent(g_hExitEvent);
	}
	return TRUE;
}

// ========================================================================================================================

DWORD WINAPI PcapListenThreadProc(LPVOID lpParameter)
{
	try
	{
		pcap_pkthdr *pPktHeader = NULL;
		const u_char *pPktData = NULL;

		while(WaitForSingleObject(g_hExitEvent, 0) != WAIT_OBJECT_0)
		{
			int pktResult = pcap_next_ex(g_pAdapter, &pPktHeader, &pPktData);
			if(pktResult < 0)
			{
				break;
			}
			else if((pktResult == 0) || (pPktHeader->caplen < sizeof(EthernetFrameHeader)))
			{
				continue;
			}

			const EthernetFrameHeader *pktEthernetFrameHeader = reinterpret_cast<const EthernetFrameHeader *>(pPktData);
			switch(pktEthernetFrameHeader->Type)
			{
				case EtherTypeArp:
					if(pPktHeader->caplen >= (sizeof(EthernetFrameHeader) + sizeof(ArpPacketHeader)))
					{
						OnListenArp(pPktHeader, pPktData);
					}
					break;

				case EtherTypeIp:
					if(pPktHeader->caplen >= (sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader)))
					{
						const IpPacketHeader *pktIpPacketHeader = reinterpret_cast<const IpPacketHeader *>(pPktData + sizeof(EthernetFrameHeader));
						switch(pktIpPacketHeader->Protocol)
						{
							case IpProtocolIcmp:
								if(pPktHeader->caplen >= (sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader) + sizeof(IcmpPacketHeader)))
								{
									OnListenIpIcmp(pPktHeader, pPktData);
								}
								break;

							case IpProtocolTcp:
								if(pPktHeader->caplen >= (sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader) + sizeof(TcpPacketHeader)))
								{
									OnListenIpTcp(pPktHeader, pPktData);
								}
								break;

							default:
								break;							
						}
					}
					break;

				default:
					break;
			}
		}
	}
	catch(const std::exception &e)
	{
		EnterCriticalSection(&g_ConsoleCriticalSection);
		std::cout << "Error: " << e.what() << std::endl;
		LeaveCriticalSection(&g_ConsoleCriticalSection);
	}

	SetEvent(g_hExitEvent);
	return 0;
}

// ========================================================================================================================

void OnListenArp(pcap_pkthdr *pPktHeader, const u_char *pPktData)
{
	const ArpPacketHeader *pktArpPacketHeader = reinterpret_cast<const ArpPacketHeader *>(pPktData + sizeof(EthernetFrameHeader));
	switch(pktArpPacketHeader->Operation)
	{
		case ArpOperationWhoHas:
			if(g_bNonAdapterIp && (pktArpPacketHeader->TargetProtocolAddress == g_SourceIp))
			{
				EnterCriticalSection(&g_ConsoleCriticalSection);
				std::cout << "ARP WHO-HAS " << ((g_SourceIp & 0x000000FF)) << "."
											<< ((g_SourceIp & 0x0000FF00) >> 8) << "."
											<< ((g_SourceIp & 0x00FF0000) >> 16) << "."
											<< ((g_SourceIp & 0xFF000000) >> 24) << " TELL "
											<< ((pktArpPacketHeader->SenderProtocolAddress & 0x000000FF)) << "."
											<< ((pktArpPacketHeader->SenderProtocolAddress & 0x0000FF00) >> 8) << "."
											<< ((pktArpPacketHeader->SenderProtocolAddress & 0x00FF0000) >> 16) << "."
											<< ((pktArpPacketHeader->SenderProtocolAddress & 0xFF000000) >> 24) << " ("
											<< std::hex
											<< std::setfill('0')
											<< std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[0]) << ":"
											<< std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[1]) << ":"
											<< std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[2]) << ":"
											<< std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[3]) << ":"
											<< std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[4]) << ":"
											<< std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[5]) << ")"
											<< std::dec << std::endl;
				LeaveCriticalSection(&g_ConsoleCriticalSection);

				const u_int arpRespPktMemSize = (sizeof(EthernetFrameHeader) + sizeof(ArpPacketHeader));
				u_char *arpRespPktData = new u_char[arpRespPktMemSize];

				EthernetFrameHeader *arpRespPktEthernetFrameHeader = reinterpret_cast<EthernetFrameHeader *>(arpRespPktData);
				SecureZeroMemory(arpRespPktEthernetFrameHeader, sizeof(EthernetFrameHeader));
				RtlCopyMemory(&arpRespPktEthernetFrameHeader->SourceMac, &g_pAdapterInfo->Address, 6);
				RtlCopyMemory(&arpRespPktEthernetFrameHeader->DestinationMac, &pktArpPacketHeader->SenderHardwareAddress, 6);
				arpRespPktEthernetFrameHeader->Type = EtherTypeArp;

				ArpPacketHeader *arpRespPktArpPacketHeader = reinterpret_cast<ArpPacketHeader *>(arpRespPktData + sizeof(EthernetFrameHeader));
				SecureZeroMemory(arpRespPktArpPacketHeader, sizeof(ArpPacketHeader));
				arpRespPktArpPacketHeader->HardwareAddressSpace = 0x0100;
				arpRespPktArpPacketHeader->ProtocolAddressSpace = 0x0008;
				arpRespPktArpPacketHeader->HardwareAddressLength = 0x06;
				arpRespPktArpPacketHeader->ProtocolAddressLength = 0x04;
				arpRespPktArpPacketHeader->Operation = ArpOperationIsAt;
				RtlCopyMemory(&arpRespPktArpPacketHeader->SenderHardwareAddress, &arpRespPktEthernetFrameHeader->SourceMac, 6);
				RtlCopyMemory(&arpRespPktArpPacketHeader->TargetHardwareAddress, &arpRespPktEthernetFrameHeader->DestinationMac, 6);
				arpRespPktArpPacketHeader->SenderProtocolAddress = g_SourceIp;
				arpRespPktArpPacketHeader->TargetProtocolAddress = pktArpPacketHeader->SenderProtocolAddress;

				pcap_sendpacket(g_pAdapter, arpRespPktData, sizeof(EthernetFrameHeader) + sizeof(ArpPacketHeader));

				delete [] arpRespPktData;
			}
			break;

		case ArpOperationIsAt:
			if(pktArpPacketHeader->SenderProtocolAddress == g_DefaultRouteIp)
			{
				for(std::map<u_int, ScanStruct *>::iterator i = g_ScanStructs.begin(); i != g_ScanStructs.end(); ++i)
				{
					ScanStruct *pScanStruct = i->second;
					
					if((pScanStruct->Mac[0] == 0x00) &&
					   (pScanStruct->Mac[1] == 0x00) &&
					   (pScanStruct->Mac[2] == 0x00) &&
					   (pScanStruct->Mac[3] == 0x00) &&
					   (pScanStruct->Mac[4] == 0x00) &&
					   (pScanStruct->Mac[5] == 0x00))
					{
						if(WaitForSingleObject(pScanStruct->hMutex, INFINITE) != WAIT_OBJECT_0)
						{
							throw std::exception("WaitForSingleObject() Failed.");
						}

						QueryPerformanceCounter(&g_lCounterLastActivity);
						RtlCopyMemory(pScanStruct->Mac, &pktArpPacketHeader->SenderHardwareAddress, 6);
						pScanStruct->Attempt = 0;

						if(pScanStruct == g_DefaultRouteScanStruct)
						{
							EnterCriticalSection(&g_ConsoleCriticalSection);
							std::cout << "ARP DEFAULT ROUTE " << ((g_DefaultRouteIp & 0x000000FF)) << "."
												<< ((g_DefaultRouteIp & 0x0000FF00) >> 8) << "."
												<< ((g_DefaultRouteIp & 0x00FF0000) >> 16) << "."
												<< ((g_DefaultRouteIp & 0xFF000000) >> 24) << " IS-AT "
												<< std::hex
												<< std::setfill('0')
												<< std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[0]) << ":"
												<< std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[1]) << ":"
												<< std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[2]) << ":"
												<< std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[3]) << ":"
												<< std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[4]) << ":"
												<< std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[5])
												<< std::dec << std::endl;
							LeaveCriticalSection(&g_ConsoleCriticalSection);
							g_DefaultRouteScanStruct = NULL;
						}

						ReleaseMutex(pScanStruct->hMutex);
					}
				}
			}

			if(g_ScanStructs.find(ntohl(pktArpPacketHeader->SenderProtocolAddress)) != g_ScanStructs.end())
			{
				ScanStruct *pScanStruct = g_ScanStructs[ntohl(pktArpPacketHeader->SenderProtocolAddress)];
				if(WaitForSingleObject(pScanStruct->hMutex, INFINITE) != WAIT_OBJECT_0)
				{
					throw std::exception("WaitForSingleObject() Failed.");
				}
				if((pScanStruct->Mac[0] == 0xFF) &&
				   (pScanStruct->Mac[1] == 0xFF) &&
				   (pScanStruct->Mac[2] == 0xFF) &&
				   (pScanStruct->Mac[3] == 0xFF) &&
				   (pScanStruct->Mac[4] == 0xFF) &&
				   (pScanStruct->Mac[5] == 0xFF))
				{
					RtlCopyMemory(pScanStruct->Mac, &pktArpPacketHeader->SenderHardwareAddress, 6);
					QueryPerformanceCounter(&g_lCounterLastActivity);
					pScanStruct->Attempt = 0;
					
					EnterCriticalSection(&g_ConsoleCriticalSection);
					std::cout << "ARP " << ((pScanStruct->Ip & 0x000000FF)) << "."
										<< ((pScanStruct->Ip & 0x0000FF00) >> 8) << "."
										<< ((pScanStruct->Ip & 0x00FF0000) >> 16) << "."
										<< ((pScanStruct->Ip & 0xFF000000) >> 24) << " IS-AT "
										<< std::hex
										<< std::setfill('0')
										<< std::setw(2) << static_cast<u_short>(pScanStruct->Mac[0]) << ":"
										<< std::setw(2) << static_cast<u_short>(pScanStruct->Mac[1]) << ":"
										<< std::setw(2) << static_cast<u_short>(pScanStruct->Mac[2]) << ":"
										<< std::setw(2) << static_cast<u_short>(pScanStruct->Mac[3]) << ":"
										<< std::setw(2) << static_cast<u_short>(pScanStruct->Mac[4]) << ":"
										<< std::setw(2) << static_cast<u_short>(pScanStruct->Mac[5])
										<< std::dec << std::endl;
					LeaveCriticalSection(&g_ConsoleCriticalSection);
				}
				ReleaseMutex(pScanStruct->hMutex);
			}
			break;

		default:
			break;
	}
}

// ========================================================================================================================

void OnListenIpIcmp(pcap_pkthdr *pPktHeader, const u_char *pPktData)
{
	const IpPacketHeader *pktIpPacketHeader = reinterpret_cast<const IpPacketHeader *>(pPktData + sizeof(EthernetFrameHeader));
	const IcmpPacketHeader *pktIcmpPacketHeader = reinterpret_cast<const IcmpPacketHeader *>(pPktData + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader));
	
	const IpPacketHeader *pktIcmpContainedIpPacketHeader = reinterpret_cast<const IpPacketHeader *>(pPktData + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader) + sizeof(IcmpPacketHeader));
	const IcmpPacketHeader *pktIcmpContainedIcmpPacketHeader = reinterpret_cast<const IcmpPacketHeader *>(pPktData + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader) + sizeof(IcmpPacketHeader) + sizeof(IpPacketHeader));
	const TcpPacketHeader *pktIcmpContainedTcpPacketHeader = reinterpret_cast<const TcpPacketHeader *>(pPktData + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader) + sizeof(IcmpPacketHeader) + sizeof(IpPacketHeader));
	const UdpPacketHeader *pktIcmpContainedUdpPacketHeader = reinterpret_cast<const UdpPacketHeader *>(pPktData + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader) + sizeof(IcmpPacketHeader) + sizeof(IpPacketHeader));
	
	if((g_ScanStructs.find(ntohl(pktIpPacketHeader->SourceAddress)) != g_ScanStructs.end()) ||
	   ((pktIcmpContainedIpPacketHeader != NULL) && (g_ScanStructs.find(ntohl(pktIcmpContainedIpPacketHeader->DestinationAddress)) != g_ScanStructs.end())))
	{
		switch(pktIcmpPacketHeader->Type)
		{
			case IcmpTypeEchoReply:
				if(g_ScanStructs.find(ntohl(pktIpPacketHeader->SourceAddress)) != g_ScanStructs.end())
				{
					ScanStruct *pScanStruct = g_ScanStructs[ntohl(pktIpPacketHeader->SourceAddress)];
					
					if(WaitForSingleObject(pScanStruct->hMutex, INFINITE) != WAIT_OBJECT_0)
					{
						throw std::exception("WaitForSingleObject() Failed.");
					}

					bool bFoundIcmpReason = false;
					for(std::vector<IcmpEventStruct>::iterator i = pScanStruct->IcmpEvents[ScanTypeIcmpEcho].begin(); i != pScanStruct->IcmpEvents[ScanTypeIcmpEcho].end(); ++i)
					{
						if(((*i).Id == pktIcmpPacketHeader->Id) && ((*i).Sequence == pktIcmpPacketHeader->Sequence))
						{
							(*i).Ip = pktIpPacketHeader->SourceAddress;
							if(WaitForSingleObject(g_hHostNamesMutex, 1000) == WAIT_OBJECT_0)
							{
								if(g_HostNames.find(pktIpPacketHeader->SourceAddress) == g_HostNames.end())
								{
									g_HostNames[pktIpPacketHeader->SourceAddress] = "";
								}
								ReleaseMutex(g_hHostNamesMutex);
							}
							else
							{
								EnterCriticalSection(&g_ConsoleCriticalSection);
								std::cout << "Warning: WaitForSingleObject(g_hHostNamesMutex, 1000) Failed." << std::endl;
								LeaveCriticalSection(&g_ConsoleCriticalSection);
							}
							(*i).Type = IcmpTypeEchoReply;

							QueryPerformanceCounter(&(*i).Response);
							pScanStruct->IcmpResponses++;

							EnterCriticalSection(&g_ConsoleCriticalSection);
							std::cout << "ICMP ECHO REPLY FROM "
									  << ((pktIpPacketHeader->SourceAddress & 0x000000FF)) << "."
									  << ((pktIpPacketHeader->SourceAddress & 0x0000FF00) >> 8) << "."
									  << ((pktIpPacketHeader->SourceAddress & 0x00FF0000) >> 16) << "."
									  << ((pktIpPacketHeader->SourceAddress & 0xFF000000) >> 24) << " TRIP "
									  << (((*i).Response.QuadPart - (*i).Transmit.QuadPart) * 1000 / g_lCounterFrequency.QuadPart) << "ms"
									  << std::endl;
							LeaveCriticalSection(&g_ConsoleCriticalSection);

							bFoundIcmpReason = true;
							break;
						}
					}
					for(std::vector<IcmpEventStruct>::iterator i = pScanStruct->IcmpEvents[ScanTypeIcmpTrace].begin(); (!bFoundIcmpReason) && (i != pScanStruct->IcmpEvents[ScanTypeIcmpTrace].end()); ++i)
					{
						if(((*i).Id == pktIcmpPacketHeader->Id) && ((*i).Sequence == pktIcmpPacketHeader->Sequence))
						{
							(*i).Ip = pktIpPacketHeader->SourceAddress;
							if(WaitForSingleObject(g_hHostNamesMutex, 1000) == WAIT_OBJECT_0)
							{
								if(g_HostNames.find(pktIpPacketHeader->SourceAddress) == g_HostNames.end())
								{
									g_HostNames[pktIpPacketHeader->SourceAddress] = "";
								}
								ReleaseMutex(g_hHostNamesMutex);
							}
							else
							{
								EnterCriticalSection(&g_ConsoleCriticalSection);
								std::cout << "Warning: WaitForSingleObject(g_hHostNamesMutex, 1000) Failed." << std::endl;
								LeaveCriticalSection(&g_ConsoleCriticalSection);
							}
							(*i).Type = IcmpTypeEchoReply;

							QueryPerformanceCounter(&(*i).Response);
							pScanStruct->IcmpResponses++;
							pScanStruct->RouteEchoResponseTtl = ntohs(pktIcmpPacketHeader->Sequence);

							EnterCriticalSection(&g_ConsoleCriticalSection);
							std::cout << "ICMP ECHO REPLY FROM "
									  << ((pktIpPacketHeader->SourceAddress & 0x000000FF)) << "."
									  << ((pktIpPacketHeader->SourceAddress & 0x0000FF00) >> 8) << "."
									  << ((pktIpPacketHeader->SourceAddress & 0x00FF0000) >> 16) << "."
									  << ((pktIpPacketHeader->SourceAddress & 0xFF000000) >> 24) << " AT "
									  << ntohs(pktIcmpPacketHeader->Sequence) << " HOPS TRIP "
									  << (((*i).Response.QuadPart - (*i).Transmit.QuadPart) * 1000 / g_lCounterFrequency.QuadPart) << "ms"
									  << std::endl;
							LeaveCriticalSection(&g_ConsoleCriticalSection);						
							break;
						}
					}

					ReleaseMutex(pScanStruct->hMutex);
				}
				break;

			case IcmpTypeUnreachable:
				if(pktIcmpContainedIpPacketHeader != NULL)
				{
					if(((pktIcmpContainedIpPacketHeader->Protocol == IpProtocolIcmp) ||
						(pktIcmpContainedIpPacketHeader->Protocol == IpProtocolTcp) ||
						(pktIcmpContainedIpPacketHeader->Protocol == IpProtocolUdp)) &&
					   (pktIcmpContainedIcmpPacketHeader != NULL))
					{
						if(g_ScanStructs.find(ntohl(pktIcmpContainedIpPacketHeader->DestinationAddress)) != g_ScanStructs.end())
						{
							ScanStruct *pScanStruct = g_ScanStructs[ntohl(pktIcmpContainedIpPacketHeader->DestinationAddress)];
							if(WaitForSingleObject(pScanStruct->hMutex, INFINITE) != WAIT_OBJECT_0)
							{
								throw std::exception("WaitForSingleObject() Failed.");
							}

							u_short hops = 0;
							u_int trip = 0;

							if(pktIcmpContainedIpPacketHeader->Protocol == IpProtocolIcmp)
							{
								for(std::vector<IcmpEventStruct>::iterator i = pScanStruct->IcmpEvents[ScanTypeIcmpTrace].begin(); i != pScanStruct->IcmpEvents[ScanTypeIcmpTrace].end(); ++i)
								{
									if(((*i).Id == pktIcmpContainedIcmpPacketHeader->Id) && (*i).Sequence == pktIcmpContainedIcmpPacketHeader->Sequence)
									{
										(*i).Ip = pktIpPacketHeader->SourceAddress;
										if(WaitForSingleObject(g_hHostNamesMutex, 1000) == WAIT_OBJECT_0)
										{
											if(g_HostNames.find(pktIpPacketHeader->SourceAddress) == g_HostNames.end())
											{
												g_HostNames[pktIpPacketHeader->SourceAddress] = "";
											}
											ReleaseMutex(g_hHostNamesMutex);
										}
										else
										{
											EnterCriticalSection(&g_ConsoleCriticalSection);
											std::cout << "Warning: WaitForSingleObject(g_hHostNamesMutex, 1000) Failed." << std::endl;
											LeaveCriticalSection(&g_ConsoleCriticalSection);
										}
										(*i).Type = IcmpTypeUnreachable;

										QueryPerformanceCounter(&(*i).Response);
										pScanStruct->IcmpResponses++;

										hops = ntohs(pktIcmpContainedIcmpPacketHeader->Sequence);
										trip = static_cast<u_int>(((*i).Response.QuadPart - (*i).Transmit.QuadPart) * 1000 / g_lCounterFrequency.QuadPart);
										break;
									}
								}
							}
							else if(pktIcmpContainedIpPacketHeader->Protocol == IpProtocolTcp)
							{
								for(std::vector<IcmpEventStruct>::iterator i = pScanStruct->IcmpEvents[ScanTypeTcpTrace].begin(); i != pScanStruct->IcmpEvents[ScanTypeTcpTrace].end(); ++i)
								{
									if((((*i).Id == pktIcmpContainedTcpPacketHeader->SourcePort) && ((*i).Sequence == pktIcmpContainedTcpPacketHeader->DestinationPort)) ||
									   (((*i).Id == pktIcmpContainedTcpPacketHeader->DestinationPort) && ((*i).Sequence == pktIcmpContainedTcpPacketHeader->SourcePort)))
									{
										(*i).Ip = pktIpPacketHeader->SourceAddress;
										if(WaitForSingleObject(g_hHostNamesMutex, 1000) == WAIT_OBJECT_0)
										{
											if(g_HostNames.find(pktIpPacketHeader->SourceAddress) == g_HostNames.end())
											{
												g_HostNames[pktIpPacketHeader->SourceAddress] = "";
											}
											ReleaseMutex(g_hHostNamesMutex);
										}
										else
										{
											EnterCriticalSection(&g_ConsoleCriticalSection);
											std::cout << "Warning: WaitForSingleObject(g_hHostNamesMutex, 1000) Failed." << std::endl;
											LeaveCriticalSection(&g_ConsoleCriticalSection);
										}
										(*i).Type = IcmpTypeUnreachable;

										QueryPerformanceCounter(&(*i).Response);
										pScanStruct->IcmpResponses++;

										if(g_ScanType & ScanTypeTraceSport)
										{
											hops = ntohs(pktIcmpContainedTcpPacketHeader->DestinationPort - g_DestinationPort) / g_uPacketAttemptCount;
										}
										else if(g_ScanType & ScanTypeTraceDport)
										{
											hops = ntohs(pktIcmpContainedTcpPacketHeader->SourcePort - g_SourcePort) / g_uPacketAttemptCount;
										}

										trip = static_cast<u_int>(((*i).Response.QuadPart - (*i).Transmit.QuadPart) * 1000 / g_lCounterFrequency.QuadPart);
										pScanStruct->RouteTcpResponseTtl = hops;
										break;
									}
								}
							}
							else if(pktIcmpContainedIpPacketHeader->Protocol == IpProtocolUdp)
							{
								for(std::vector<IcmpEventStruct>::iterator i = pScanStruct->IcmpEvents[ScanTypeUdpTrace].begin(); i != pScanStruct->IcmpEvents[ScanTypeUdpTrace].end(); ++i)
								{
									if((((*i).Id == pktIcmpContainedUdpPacketHeader->SourcePort) && ((*i).Sequence == pktIcmpContainedUdpPacketHeader->DestinationPort)) ||
									   (((*i).Id == pktIcmpContainedUdpPacketHeader->DestinationPort) && ((*i).Sequence == pktIcmpContainedUdpPacketHeader->SourcePort)))
									{
										(*i).Ip = pktIpPacketHeader->SourceAddress;
										if(WaitForSingleObject(g_hHostNamesMutex, 1000) == WAIT_OBJECT_0)
										{
											if(g_HostNames.find(pktIpPacketHeader->SourceAddress) == g_HostNames.end())
											{
												g_HostNames[pktIpPacketHeader->SourceAddress] = "";
											}
											ReleaseMutex(g_hHostNamesMutex);
										}
										else
										{
											EnterCriticalSection(&g_ConsoleCriticalSection);
											std::cout << "Warning: WaitForSingleObject(g_hHostNamesMutex, 1000) Failed." << std::endl;
											LeaveCriticalSection(&g_ConsoleCriticalSection);
										}
										(*i).Type = IcmpTypeUnreachable;

										QueryPerformanceCounter(&(*i).Response);
										pScanStruct->IcmpResponses++;

										if(g_ScanType & ScanTypeTraceSport)
										{
											hops = ntohs(pktIcmpContainedUdpPacketHeader->DestinationPort - g_DestinationPort) / g_uPacketAttemptCount;
										}
										else if(g_ScanType & ScanTypeTraceDport)
										{
											hops = ntohs(pktIcmpContainedUdpPacketHeader->SourcePort - g_SourcePort) / g_uPacketAttemptCount;
										}

										trip = static_cast<u_int>(((*i).Response.QuadPart - (*i).Transmit.QuadPart) * 1000 / g_lCounterFrequency.QuadPart);
										pScanStruct->RouteUdpResponseTtl = hops;
										break;
									}
								}
							}
							
							EnterCriticalSection(&g_ConsoleCriticalSection);
							std::cout << "ICMP UNREACHABLE FROM "
									  << ((pktIpPacketHeader->SourceAddress & 0x000000FF)) << "."
									  << ((pktIpPacketHeader->SourceAddress & 0x0000FF00) >> 8) << "."
									  << ((pktIpPacketHeader->SourceAddress & 0x00FF0000) >> 16) << "."
									  << ((pktIpPacketHeader->SourceAddress & 0xFF000000) >> 24)  << " AT "
									  << hops << " HOPS FOR "
									  << ((pktIcmpContainedIpPacketHeader->DestinationAddress & 0x000000FF)) << "."
									  << ((pktIcmpContainedIpPacketHeader->DestinationAddress & 0x0000FF00) >> 8) << "."
									  << ((pktIcmpContainedIpPacketHeader->DestinationAddress & 0x00FF0000) >> 16) << "."
									  << ((pktIcmpContainedIpPacketHeader->DestinationAddress & 0xFF000000) >> 24) << " TRIP "
									  << trip << "ms ";
							switch(pktIcmpPacketHeader->Code)
							{
								case IcmpUnreachableCodeNetworkUnreachable:
									std::cout << "NETWORK UNREACHABLE";
									break;
								case IcmpUnreachableCodeHostUnreachable:
									std::cout << "HOST UNREACHABLE";
									break;
								case IcmpUnreachableCodeProtocolUnreachable:
									std::cout << "PROTOCOL UNREACHABLE";
									break;
								case IcmpUnreachableCodePortUnreachable:
									std::cout << "PORT UNREACHABLE";
									break;
								case IcmpUnreachableCodeDatagramUnfragmentable:
									std::cout << "UNFRAGMENTABLE";
									break;
								case IcmpUnreachableCodeSourceRouteFailed:
									std::cout << "SOURCE ROUTE FAILED";
									break;
								case IcmpUnreachableCodeDestinationNetworkUnknown:
									std::cout << "DESTINATION NETWORK UNKNOWN";
									break;
								case IcmpUnreachableCodeDestinationHostUnknown:
									std::cout << "DESTINATION HOST UNKNOWN";
									break;
								case IcmpUnreachableCodeSourceHostIsolated:
									std::cout << "HOST ISOLATED";
									break;
								case IcmpUnreachableCodeDestinationNetworkProhibited:
									std::cout << "NETWORK PROHIBITED";
									break;
								case IcmpUnreachableCodeDestinationHostProhibited:
									std::cout << "HOST PROHIBITED";
									break;
								case IcmpUnreachableCodeDestinationNetworkUnreachableTos:
									std::cout << "NETWORK UNREACHABLE TOS";
									break;
								case IcmpUnreachableCodeDestinationHostUnreachableTos:
									std::cout << "HOST UNREACHABLE TOS";
									break;
								case IcmpUnreachableCodeAdministrativelyProhibited:
									std::cout << "ADMINISTRATIVELY PROHIBITED";
									break;
								case IcmpUnreachableCodeHostPrecedenceViolation:
									std::cout << "HOST PRECEDENCE VIOLATION";
									break;
								case IcmpUnreachableCodePrecedenceCutoff:
									std::cout << "PRECEDENCE CUTOFF";
									break;
							}
							std::cout << std::endl;
							LeaveCriticalSection(&g_ConsoleCriticalSection);
							ReleaseMutex(pScanStruct->hMutex);
						}
					}
				}
				break;

			case IcmpTypeRouterAdvertisement:
				if(g_ScanStructs.find(ntohl(pktIpPacketHeader->SourceAddress)) != g_ScanStructs.end())
				{
					ScanStruct *pScanStruct = g_ScanStructs[ntohl(pktIpPacketHeader->SourceAddress)];
					if(WaitForSingleObject(pScanStruct->hMutex, INFINITE) != WAIT_OBJECT_0)
					{
						throw std::exception("WaitForSingleObject() Failed.");
					}

					for(std::vector<IcmpEventStruct>::iterator i = pScanStruct->IcmpEvents[ScanTypeIcmpRouter].begin(); i != pScanStruct->IcmpEvents[ScanTypeIcmpRouter].end(); ++i)
					{
						if(((*i).Id == pktIcmpPacketHeader->Id) && (*i).Sequence == pktIcmpPacketHeader->Sequence)
						{
							(*i).Ip = pktIpPacketHeader->SourceAddress;
							if(WaitForSingleObject(g_hHostNamesMutex, 1000) == WAIT_OBJECT_0)
							{
								if(g_HostNames.find(pktIpPacketHeader->SourceAddress) == g_HostNames.end())
								{
									g_HostNames[pktIpPacketHeader->SourceAddress] = "";
								}
								ReleaseMutex(g_hHostNamesMutex);
							}
							else
							{
								EnterCriticalSection(&g_ConsoleCriticalSection);
								std::cout << "Warning: WaitForSingleObject(g_hHostNamesMutex, 1000) Failed." << std::endl;
								LeaveCriticalSection(&g_ConsoleCriticalSection);
							}
							(*i).Type = IcmpTypeTimestampReply;

							QueryPerformanceCounter(&(*i).Response);
							pScanStruct->IcmpResponses++;

							EnterCriticalSection(&g_ConsoleCriticalSection);
							std::cout << "ICMP ROUTER REPLY FROM "
									  << ((pktIpPacketHeader->SourceAddress & 0x000000FF)) << "."
									  << ((pktIpPacketHeader->SourceAddress & 0x0000FF00) >> 8) << "."
									  << ((pktIpPacketHeader->SourceAddress & 0x00FF0000) >> 16) << "."
									  << ((pktIpPacketHeader->SourceAddress & 0xFF000000) >> 24) << " TRIP "
									  << (((*i).Response.QuadPart - (*i).Transmit.QuadPart) * 1000 / g_lCounterFrequency.QuadPart) << "ms"
									  << std::endl;
							LeaveCriticalSection(&g_ConsoleCriticalSection);
							break;
						}
					}

					ReleaseMutex(pScanStruct->hMutex);
				}
				break;
				break;

			case IcmpTypeTimeExceeded:
				if(pktIcmpContainedIpPacketHeader != NULL)
				{
					if(((pktIcmpContainedIpPacketHeader->Protocol == IpProtocolIcmp) ||
						(pktIcmpContainedIpPacketHeader->Protocol == IpProtocolTcp) ||
						(pktIcmpContainedIpPacketHeader->Protocol == IpProtocolUdp)) &&
					   (pktIcmpContainedIcmpPacketHeader != NULL))
					{
						if(g_ScanStructs.find(ntohl(pktIcmpContainedIpPacketHeader->DestinationAddress)) != g_ScanStructs.end())
						{
							ScanStruct *pScanStruct = g_ScanStructs[ntohl(pktIcmpContainedIpPacketHeader->DestinationAddress)];
							if(WaitForSingleObject(pScanStruct->hMutex, INFINITE) != WAIT_OBJECT_0)
							{
								throw std::exception("WaitForSingleObject() Failed.");
							}

							u_int hops = 0;
							u_int trip = 0;

							if(pktIcmpContainedIpPacketHeader->Protocol == IpProtocolIcmp)
							{
								for(std::vector<IcmpEventStruct>::iterator i = pScanStruct->IcmpEvents[ScanTypeIcmpTrace].begin(); i != pScanStruct->IcmpEvents[ScanTypeIcmpTrace].end(); ++i)
								{
									if(((*i).Id == pktIcmpContainedIcmpPacketHeader->Id) && (*i).Sequence == pktIcmpContainedIcmpPacketHeader->Sequence)
									{
										(*i).Ip = pktIpPacketHeader->SourceAddress;
										if(WaitForSingleObject(g_hHostNamesMutex, 1000) == WAIT_OBJECT_0)
										{
											if(g_HostNames.find(pktIpPacketHeader->SourceAddress) == g_HostNames.end())
											{
												g_HostNames[pktIpPacketHeader->SourceAddress] = "";
											}
											ReleaseMutex(g_hHostNamesMutex);
										}
										else
										{
											EnterCriticalSection(&g_ConsoleCriticalSection);
											std::cout << "Warning: WaitForSingleObject(g_hHostNamesMutex, 1000) Failed." << std::endl;
											LeaveCriticalSection(&g_ConsoleCriticalSection);
										}
										(*i).Type = IcmpTypeTimeExceeded;

										QueryPerformanceCounter(&(*i).Response);
										pScanStruct->IcmpResponses++;

										hops = ntohs(pktIcmpContainedIcmpPacketHeader->Sequence);
										trip = static_cast<u_int>(((*i).Response.QuadPart - (*i).Transmit.QuadPart) * 1000 / g_lCounterFrequency.QuadPart);
										break;
									}
								}
							}
							else if(pktIcmpContainedIpPacketHeader->Protocol == IpProtocolTcp)
							{
								for(std::vector<IcmpEventStruct>::iterator i = pScanStruct->IcmpEvents[ScanTypeTcpTrace].begin(); i != pScanStruct->IcmpEvents[ScanTypeTcpTrace].end(); ++i)
								{
									if((((*i).Id == pktIcmpContainedTcpPacketHeader->SourcePort) && ((*i).Sequence == pktIcmpContainedTcpPacketHeader->DestinationPort)) ||
									   (((*i).Id == pktIcmpContainedTcpPacketHeader->DestinationPort) && ((*i).Sequence == pktIcmpContainedTcpPacketHeader->SourcePort)))
									{
										(*i).Ip = pktIpPacketHeader->SourceAddress;
										if(WaitForSingleObject(g_hHostNamesMutex, 1000) == WAIT_OBJECT_0)
										{
											if(g_HostNames.find(pktIpPacketHeader->SourceAddress) == g_HostNames.end())
											{
												g_HostNames[pktIpPacketHeader->SourceAddress] = "";
											}
											ReleaseMutex(g_hHostNamesMutex);
										}
										else
										{
											EnterCriticalSection(&g_ConsoleCriticalSection);
											std::cout << "Warning: WaitForSingleObject(g_hHostNamesMutex, 1000) Failed." << std::endl;
											LeaveCriticalSection(&g_ConsoleCriticalSection);
										}
										(*i).Type = IcmpTypeTimeExceeded;

										QueryPerformanceCounter(&(*i).Response);
										pScanStruct->IcmpResponses++;

										if(g_ScanType & ScanTypeTraceSport)
										{
											hops = ntohs(pktIcmpContainedTcpPacketHeader->DestinationPort - g_DestinationPort) / g_uPacketAttemptCount;
										}
										else if(g_ScanType & ScanTypeTraceDport)
										{
											hops = ntohs(pktIcmpContainedTcpPacketHeader->SourcePort - g_SourcePort) / g_uPacketAttemptCount;
										}

										trip = static_cast<u_int>(((*i).Response.QuadPart - (*i).Transmit.QuadPart) * 1000 / g_lCounterFrequency.QuadPart);
										break;
									}
								}
							}
							else if(pktIcmpContainedIpPacketHeader->Protocol == IpProtocolUdp)
							{
								for(std::vector<IcmpEventStruct>::iterator i = pScanStruct->IcmpEvents[ScanTypeUdpTrace].begin(); i != pScanStruct->IcmpEvents[ScanTypeUdpTrace].end(); ++i)
								{
									if((((*i).Id == pktIcmpContainedUdpPacketHeader->SourcePort) && ((*i).Sequence == pktIcmpContainedUdpPacketHeader->DestinationPort)) ||
									   (((*i).Id == pktIcmpContainedUdpPacketHeader->DestinationPort) && ((*i).Sequence == pktIcmpContainedUdpPacketHeader->SourcePort)))
									{
										(*i).Ip = pktIpPacketHeader->SourceAddress;
										if(WaitForSingleObject(g_hHostNamesMutex, 1000) == WAIT_OBJECT_0)
										{
											if(g_HostNames.find(pktIpPacketHeader->SourceAddress) == g_HostNames.end())
											{
												g_HostNames[pktIpPacketHeader->SourceAddress] = "";
											}
											ReleaseMutex(g_hHostNamesMutex);
										}
										else
										{
											EnterCriticalSection(&g_ConsoleCriticalSection);
											std::cout << "Warning: WaitForSingleObject(g_hHostNamesMutex, 1000) Failed." << std::endl;
											LeaveCriticalSection(&g_ConsoleCriticalSection);
										}
										(*i).Type = IcmpTypeTimeExceeded;

										QueryPerformanceCounter(&(*i).Response);
										pScanStruct->IcmpResponses++;

										if(g_ScanType & ScanTypeTraceSport)
										{
											hops = ntohs(pktIcmpContainedUdpPacketHeader->DestinationPort - g_DestinationPort) / g_uPacketAttemptCount;
										}
										else if(g_ScanType & ScanTypeTraceDport)
										{
											hops = ntohs(pktIcmpContainedUdpPacketHeader->SourcePort - g_SourcePort) / g_uPacketAttemptCount;
										}

										trip = static_cast<u_int>(((*i).Response.QuadPart - (*i).Transmit.QuadPart) * 1000 / g_lCounterFrequency.QuadPart);
										break;
									}
								}
							}

							EnterCriticalSection(&g_ConsoleCriticalSection);
							std::cout << "ICMP TIME EXCEEDED FROM "
									  << ((pktIpPacketHeader->SourceAddress & 0x000000FF)) << "."
									  << ((pktIpPacketHeader->SourceAddress & 0x0000FF00) >> 8) << "."
									  << ((pktIpPacketHeader->SourceAddress & 0x00FF0000) >> 16) << "."
									  << ((pktIpPacketHeader->SourceAddress & 0xFF000000) >> 24)  << " AT "
									  << hops << " HOPS FOR "
									  << ((pktIcmpContainedIpPacketHeader->DestinationAddress & 0x000000FF)) << "."
									  << ((pktIcmpContainedIpPacketHeader->DestinationAddress & 0x0000FF00) >> 8) << "."
									  << ((pktIcmpContainedIpPacketHeader->DestinationAddress & 0x00FF0000) >> 16) << "."
									  << ((pktIcmpContainedIpPacketHeader->DestinationAddress & 0xFF000000) >> 24) << " TRIP "
									  << trip << "MS ";
							switch(pktIcmpPacketHeader->Code)
							{
								case IcmpTimeExceededCodeInTransit:
									std::cout << "IN TRANSIT";
									break;
								case IcmpTimeExceededCodeFragmentReassembly:
									std::cout << "IN FRAGMENT REASSEMBLY";
									break;
							}
							std::cout << std::endl;
							LeaveCriticalSection(&g_ConsoleCriticalSection);
							
							ReleaseMutex(pScanStruct->hMutex);
						}
					}
				}
				break;

			case IcmpTypeTimestampReply:
				if(g_ScanStructs.find(ntohl(pktIpPacketHeader->SourceAddress)) != g_ScanStructs.end())
				{
					ScanStruct *pScanStruct = g_ScanStructs[ntohl(pktIpPacketHeader->SourceAddress)];
					if(WaitForSingleObject(pScanStruct->hMutex, INFINITE) != WAIT_OBJECT_0)
					{
						throw std::exception("WaitForSingleObject() Failed.");
					}

					for(std::vector<IcmpEventStruct>::iterator i = pScanStruct->IcmpEvents[ScanTypeIcmpTimestamp].begin(); i != pScanStruct->IcmpEvents[ScanTypeIcmpTimestamp].end(); ++i)
					{
						if(((*i).Id == pktIcmpPacketHeader->Id) && (*i).Sequence == pktIcmpPacketHeader->Sequence)
						{
							(*i).Ip = pktIpPacketHeader->SourceAddress;
							if(WaitForSingleObject(g_hHostNamesMutex, 1000) == WAIT_OBJECT_0)
							{
								if(g_HostNames.find(pktIpPacketHeader->SourceAddress) == g_HostNames.end())
								{
									g_HostNames[pktIpPacketHeader->SourceAddress] = "";
								}
								ReleaseMutex(g_hHostNamesMutex);
							}
							else
							{
								EnterCriticalSection(&g_ConsoleCriticalSection);
								std::cout << "Warning: WaitForSingleObject(g_hHostNamesMutex, 1000) Failed." << std::endl;
								LeaveCriticalSection(&g_ConsoleCriticalSection);
							}
							(*i).Type = IcmpTypeTimestampReply;

							QueryPerformanceCounter(&(*i).Response);
							pScanStruct->IcmpResponses++;

							EnterCriticalSection(&g_ConsoleCriticalSection);
							std::cout << "ICMP TIMESTAMP REPLY FROM "
									  << ((pktIpPacketHeader->SourceAddress & 0x000000FF)) << "."
									  << ((pktIpPacketHeader->SourceAddress & 0x0000FF00) >> 8) << "."
									  << ((pktIpPacketHeader->SourceAddress & 0x00FF0000) >> 16) << "."
									  << ((pktIpPacketHeader->SourceAddress & 0xFF000000) >> 24) << " TRIP "
									  << (((*i).Response.QuadPart - (*i).Transmit.QuadPart) * 1000 / g_lCounterFrequency.QuadPart) << "ms"
									  << std::endl;
							LeaveCriticalSection(&g_ConsoleCriticalSection);
							break;
						}
					}

					ReleaseMutex(pScanStruct->hMutex);
				}
				break;

			case IcmpTypeInformationReply:
				if(g_ScanStructs.find(ntohl(pktIpPacketHeader->SourceAddress)) != g_ScanStructs.end())
				{
					ScanStruct *pScanStruct = g_ScanStructs[ntohl(pktIpPacketHeader->SourceAddress)];
					if(WaitForSingleObject(pScanStruct->hMutex, INFINITE) != WAIT_OBJECT_0)
					{
						throw std::exception("WaitForSingleObject() Failed.");
					}

					for(std::vector<IcmpEventStruct>::iterator i = pScanStruct->IcmpEvents[ScanTypeIcmpInformation].begin(); i != pScanStruct->IcmpEvents[ScanTypeIcmpInformation].end(); ++i)
					{
						if(((*i).Id == pktIcmpPacketHeader->Id) && (*i).Sequence == pktIcmpPacketHeader->Sequence)
						{
							(*i).Ip = pktIpPacketHeader->SourceAddress;
							if(WaitForSingleObject(g_hHostNamesMutex, 1000) == WAIT_OBJECT_0)
							{
								if(g_HostNames.find(pktIpPacketHeader->SourceAddress) == g_HostNames.end())
								{
									g_HostNames[pktIpPacketHeader->SourceAddress] = "";
								}
								ReleaseMutex(g_hHostNamesMutex);
							}
							else
							{
								EnterCriticalSection(&g_ConsoleCriticalSection);
								std::cout << "Warning: WaitForSingleObject(g_hHostNamesMutex, 1000) Failed." << std::endl;
								LeaveCriticalSection(&g_ConsoleCriticalSection);
							}
							(*i).Type = IcmpTypeInformationReply;

							QueryPerformanceCounter(&(*i).Response);
							pScanStruct->IcmpResponses++;

							EnterCriticalSection(&g_ConsoleCriticalSection);
							std::cout << "ICMP INFORMATION REPLY FROM "
									  << ((pktIpPacketHeader->SourceAddress & 0x000000FF)) << "."
									  << ((pktIpPacketHeader->SourceAddress & 0x0000FF00) >> 8) << "."
									  << ((pktIpPacketHeader->SourceAddress & 0x00FF0000) >> 16) << "."
									  << ((pktIpPacketHeader->SourceAddress & 0xFF000000) >> 24) << " TRIP "
									  << (((*i).Response.QuadPart - (*i).Transmit.QuadPart) * 1000 / g_lCounterFrequency.QuadPart) << "ms"
									  << std::endl;
							LeaveCriticalSection(&g_ConsoleCriticalSection);
							break;
						}
					}

					ReleaseMutex(pScanStruct->hMutex);
				}
				break;

			case IcmpTypeNetmaskReply:
				if(g_ScanStructs.find(ntohl(pktIpPacketHeader->SourceAddress)) != g_ScanStructs.end())
				{
					ScanStruct *pScanStruct = g_ScanStructs[ntohl(pktIpPacketHeader->SourceAddress)];
					if(WaitForSingleObject(pScanStruct->hMutex, INFINITE) != WAIT_OBJECT_0)
					{
						throw std::exception("WaitForSingleObject() Failed.");
					}

					for(std::vector<IcmpEventStruct>::iterator i = pScanStruct->IcmpEvents[ScanTypeIcmpNetmask].begin(); i != pScanStruct->IcmpEvents[ScanTypeIcmpNetmask].end(); ++i)
					{
						if(((*i).Id == pktIcmpPacketHeader->Id) && (*i).Sequence == pktIcmpPacketHeader->Sequence)
						{
							(*i).Ip = pktIpPacketHeader->SourceAddress;
							if(WaitForSingleObject(g_hHostNamesMutex, 1000) == WAIT_OBJECT_0)
							{
								if(g_HostNames.find(pktIpPacketHeader->SourceAddress) == g_HostNames.end())
								{
									g_HostNames[pktIpPacketHeader->SourceAddress] = "";
								}
								ReleaseMutex(g_hHostNamesMutex);
							}
							else
							{
								EnterCriticalSection(&g_ConsoleCriticalSection);
								std::cout << "Warning: WaitForSingleObject(g_hHostNamesMutex, 1000) Failed." << std::endl;
								LeaveCriticalSection(&g_ConsoleCriticalSection);
							}
							(*i).Type = IcmpTypeNetmaskReply;

							QueryPerformanceCounter(&(*i).Response);
							pScanStruct->IcmpResponses++;

							EnterCriticalSection(&g_ConsoleCriticalSection);
							std::cout << "ICMP NETMASK REPLY FROM "
									  << ((pktIpPacketHeader->SourceAddress & 0x000000FF)) << "."
									  << ((pktIpPacketHeader->SourceAddress & 0x0000FF00) >> 8) << "."
									  << ((pktIpPacketHeader->SourceAddress & 0x00FF0000) >> 16) << "."
									  << ((pktIpPacketHeader->SourceAddress & 0xFF000000) >> 24) << " TRIP "
									  << (((*i).Response.QuadPart - (*i).Transmit.QuadPart) * 1000 / g_lCounterFrequency.QuadPart) << "ms"
									  << std::endl;
							LeaveCriticalSection(&g_ConsoleCriticalSection);
							break;
						}
					}

					ReleaseMutex(pScanStruct->hMutex);
				}
				break;

			default:
				break;
		}
	}
}

// ========================================================================================================================

void OnListenIpTcp(pcap_pkthdr *pPktHeader, const u_char *pPktData)
{
	const IpPacketHeader *pktIpPacketHeader = reinterpret_cast<const IpPacketHeader *>(pPktData + sizeof(EthernetFrameHeader));
	if(g_ScanStructs.find(ntohl(pktIpPacketHeader->SourceAddress)) != g_ScanStructs.end())
	{
		const TcpPacketHeader *pktTcpPacketHeader = reinterpret_cast<const TcpPacketHeader *>(pPktData + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader));
		
		ScanStruct *pScanStruct = g_ScanStructs[ntohl(pktIpPacketHeader->SourceAddress)];
		if(((ntohl(pktTcpPacketHeader->AcknowledgementNumber) - 1) == pScanStruct->PacketIsnBase) && (pktIpPacketHeader->SourceAddress == pScanStruct->Ip))
		{
			if(WaitForSingleObject(pScanStruct->hMutex, INFINITE) != WAIT_OBJECT_0)
			{
				throw std::exception("WaitForSingleObject() Failed.");
			}
		
			for(std::vector<IcmpEventStruct>::iterator i = pScanStruct->IcmpEvents[ScanTypeTcpTrace].begin(); i != pScanStruct->IcmpEvents[ScanTypeTcpTrace].end(); ++i)
			{
				if(((((*i).Id == pktTcpPacketHeader->SourcePort) && ((*i).Sequence == pktTcpPacketHeader->DestinationPort)) ||
				    (((*i).Id == pktTcpPacketHeader->DestinationPort) && ((*i).Sequence == pktTcpPacketHeader->SourcePort))) &&
				   ((*i).Response.QuadPart == 0xFFFFFFFFFFFFFFFF))
				{
					(*i).Ip = pktIpPacketHeader->SourceAddress;
					if(WaitForSingleObject(g_hHostNamesMutex, 1000) == WAIT_OBJECT_0)
					{
						if(g_HostNames.find(pktIpPacketHeader->SourceAddress) == g_HostNames.end())
						{
							g_HostNames[pktIpPacketHeader->SourceAddress] = "";
						}
						ReleaseMutex(g_hHostNamesMutex);
					}
					else
					{
						EnterCriticalSection(&g_ConsoleCriticalSection);
						std::cout << "Warning: WaitForSingleObject(g_hHostNamesMutex, 1000) Failed." << std::endl;
						LeaveCriticalSection(&g_ConsoleCriticalSection);
					}
					(*i).Type = 0xFFFF;

					u_short hops = 0;
					u_short trip = 0;

					if(g_ScanType & ScanTypeTraceSport)
					{
						hops = ntohs(pktTcpPacketHeader->SourcePort - g_DestinationPort) / g_uPacketAttemptCount;
					}
					else if(g_ScanType & ScanTypeTraceDport)
					{
						hops = ntohs(pktTcpPacketHeader->DestinationPort - g_SourcePort) / g_uPacketAttemptCount;
					}

					QueryPerformanceCounter(&(*i).Response);
					trip = static_cast<u_int>(((*i).Response.QuadPart - (*i).Transmit.QuadPart) * 1000 / g_lCounterFrequency.QuadPart);

					pScanStruct->IcmpResponses++;
					pScanStruct->RouteTcpResponseTtl = hops;
					
					switch(pktTcpPacketHeader->Flags)
					{
						case (TcpFlagSyn | TcpFlagAck):
							EnterCriticalSection(&g_ConsoleCriticalSection);
							std::cout << "TCP SYN+ACK " << ((pScanStruct->Ip & 0x000000FF)) << "."
														<< ((pScanStruct->Ip & 0x0000FF00) >> 8) << "."
														<< ((pScanStruct->Ip & 0x00FF0000) >> 16) << "."
														<< ((pScanStruct->Ip & 0xFF000000) >> 24) << " "
														<< ntohs(pktTcpPacketHeader->SourcePort) << " AT "
													    << hops << " HOPS TRIP "
														<< trip << "ms " << std::endl;
							LeaveCriticalSection(&g_ConsoleCriticalSection);
							QueryPerformanceCounter(&g_lCounterLastActivity);
							(*i).Type = 0xFFFE;
							break;

						case (TcpFlagRst | TcpFlagAck):
							EnterCriticalSection(&g_ConsoleCriticalSection);
							std::cout << "TCP RST+ACK "	<< ((pScanStruct->Ip & 0x000000FF)) << "."
														<< ((pScanStruct->Ip & 0x0000FF00) >> 8) << "."
														<< ((pScanStruct->Ip & 0x00FF0000) >> 16) << "."
														<< ((pScanStruct->Ip & 0xFF000000) >> 24) << " "
														<< ntohs(pktTcpPacketHeader->SourcePort) << " AT "
													    << hops << " HOPS TRIP "
														<< trip << "ms " << std::endl;
							LeaveCriticalSection(&g_ConsoleCriticalSection);
							QueryPerformanceCounter(&g_lCounterLastActivity);
							(*i).Type = 0xFFFD;
							break;
					}
					break;
				}
			}

			ReleaseMutex(pScanStruct->hMutex);
		}
	}
}

// ========================================================================================================================

DWORD CALLBACK PcapScanThreadProc(LPVOID lpParameter)
{	
	// ----------------
	// Packet Templates
	// ----------------

	EthernetFrameHeader pktEthernetFrameHeader;
	SecureZeroMemory(&pktEthernetFrameHeader, sizeof(EthernetFrameHeader));
	RtlCopyMemory(&pktEthernetFrameHeader.SourceMac, &g_pAdapterInfo->Address, 6);
	pktEthernetFrameHeader.Type = 0;

	ArpPacketHeader pktArpPacketHeader;
	SecureZeroMemory(&pktArpPacketHeader, sizeof(ArpPacketHeader));
	pktArpPacketHeader.HardwareAddressSpace = 0x0100;
	pktArpPacketHeader.ProtocolAddressSpace = 0x0008;
	pktArpPacketHeader.HardwareAddressLength = 0x06;
	pktArpPacketHeader.ProtocolAddressLength = 0x04;
	pktArpPacketHeader.Operation = 0;
	RtlCopyMemory(&pktArpPacketHeader.SenderHardwareAddress, &pktEthernetFrameHeader.SourceMac, 6);
	RtlZeroMemory(&pktArpPacketHeader.TargetHardwareAddress, 6);
	pktArpPacketHeader.SenderProtocolAddress = g_SourceIp;
	pktArpPacketHeader.TargetProtocolAddress = 0;

	IpPacketHeader pktIpPacketHeader;
	SecureZeroMemory(&pktIpPacketHeader, sizeof(IpPacketHeader));
	pktIpPacketHeader.VersionInternetHeaderLength = 0x40 | (sizeof(IpPacketHeader) / 4);
	pktIpPacketHeader.TypeOfService = 0;
	pktIpPacketHeader.TotalLength = 0;
	pktIpPacketHeader.Identification = 0x0800;
	pktIpPacketHeader.FlagsFragmentOffset = 0;
	pktIpPacketHeader.TimeToLive = 0xFF;
	pktIpPacketHeader.Protocol = 0;
	pktIpPacketHeader.Crc = 0;
	pktIpPacketHeader.SourceAddress = g_SourceIp;
	pktIpPacketHeader.DestinationAddress = 0;

	ChecksumPseudoHeader pktChecksumPseudoHeader;
	SecureZeroMemory(&pktChecksumPseudoHeader, sizeof(ChecksumPseudoHeader));
	pktChecksumPseudoHeader.SourceAddress = g_SourceIp;
	pktChecksumPseudoHeader.DestinationAddress = 0;
	pktChecksumPseudoHeader.Zero = 0;
	pktChecksumPseudoHeader.Protocol = 0;
	pktChecksumPseudoHeader.Length = 0;

	IcmpPacketHeader pktIcmpPacketHeader;
	SecureZeroMemory(&pktIcmpPacketHeader, sizeof(IcmpPacketHeader));

	TcpPacketHeader pktTcpPacketHeader;
	SecureZeroMemory(&pktTcpPacketHeader, sizeof(TcpPacketHeader));
	pktTcpPacketHeader.SourcePort = 0;
	pktTcpPacketHeader.DestinationPort = 0;
	pktTcpPacketHeader.SequenceNumber = 0;
	pktTcpPacketHeader.AcknowledgementNumber = 0;
	pktTcpPacketHeader.DataOffset = (sizeof(TcpPacketHeader) / 4) << 4;
	pktTcpPacketHeader.Flags = 0;
	pktTcpPacketHeader.Window = 0x0040;
	pktTcpPacketHeader.UrgentPointer = 0;
	pktTcpPacketHeader.Checksum = 0;

	UdpPacketHeader pktUdpPacketHeader;
	SecureZeroMemory(&pktUdpPacketHeader, sizeof(UdpPacketHeader));

	char pktBuffer[36]; // Note: Ensure (sizeof(pktBuffer)) % 2 == 0.
	RtlCopyMemory(&pktBuffer, "Scamp (C)2007-2008 http://int3.ws/\x00\x00", 36);

	// -----------------
	// Packet Generation
	// -----------------

	const u_int pktDataSize = sizeof(pcap_pkthdr) +
							  sizeof(EthernetFrameHeader) +
							  sizeof(IpPacketHeader) +
							  max(sizeof(IcmpPacketHeader), sizeof(UdpPacketHeader)) +
							  sizeof(pktBuffer);

	pcap_pkthdr pktHeader;
	pktHeader.caplen = pktHeader.len = 0;
	pktHeader.ts.tv_sec = pktHeader.ts.tv_usec = 0;

	pcap_send_queue *pktSendQueue = NULL;
	u_char *pktData = new u_char[pktDataSize];
	
	ScanStruct *pScanStruct = NULL;
	std::map<u_int, ScanStruct *>::iterator pScanStructIter = g_ScanStructs.begin();

	LARGE_INTEGER lCounterNow;
	QueryPerformanceCounter(&lCounterNow);
	QueryPerformanceCounter(&g_lCounterLastActivity);

	try
	{
		while((WaitForSingleObject(g_hExitEvent, 0) != WAIT_OBJECT_0) &&
			  ((g_lCounterLastActivity.QuadPart + (g_lCounterFrequency.QuadPart * g_uWaitEndMs) / 1000) > lCounterNow.QuadPart))
		{
			u_int pktSendQueueMemSize = (g_uPacketQueueCount * pktDataSize * 2);

			pktSendQueue = pcap_sendqueue_alloc(pktSendQueueMemSize);
			if(pktSendQueue == NULL)
			{
				throw std::exception("pcap_sendqueue_alloc() Failed.");
			}

			std::map<u_int, ScanStruct *>::iterator pScanStructLoopIter = pScanStructIter;
			
			u_int currentQueueCount = 0;
			while(currentQueueCount < g_uPacketQueueCount)
			{
				if(pScanStruct != NULL)
				{
					ReleaseMutex(pScanStruct->hMutex);
					pScanStruct = NULL;
				}
				pScanStruct = pScanStructIter->second;
				if(WaitForSingleObject(pScanStruct->hMutex, INFINITE) != WAIT_OBJECT_0)
				{
					throw std::exception("WaitForSingleObject() Failed.");
				}

				if(((pScanStruct->Mac[0] == 0xFF) &&
					(pScanStruct->Mac[1] == 0xFF) &&
					(pScanStruct->Mac[2] == 0xFF) &&
					(pScanStruct->Mac[3] == 0xFF) &&
					(pScanStruct->Mac[4] == 0xFF) &&
					(pScanStruct->Mac[5] == 0xFF)) ||
				   ((pScanStruct->Mac[0] == 0x00) &&
					(pScanStruct->Mac[1] == 0x00) &&
					(pScanStruct->Mac[2] == 0x00) &&
					(pScanStruct->Mac[3] == 0x00) &&
					(pScanStruct->Mac[4] == 0x00) &&
					(pScanStruct->Mac[5] == 0x00)))
				{
					if((pScanStruct->Attempt < g_uPacketAttemptCount) &&
					   (pScanStruct->lCounterLastPacketTime.QuadPart + ((g_lCounterFrequency.QuadPart * g_uPacketIntervalMs) / 1000) <= lCounterNow.QuadPart))
					{
						pktEthernetFrameHeader.Type = EtherTypeArp;
						RtlCopyMemory(&pktEthernetFrameHeader.DestinationMac, &pScanStruct->Mac, 6);

						pktArpPacketHeader.Operation = ArpOperationWhoHas;
						pktArpPacketHeader.TargetProtocolAddress = 0;
						RtlCopyMemory(&pktArpPacketHeader.TargetHardwareAddress, &pScanStruct->Mac, 6);
						
						if(pScanStruct->Mac[0] == 0x00)
						{
							if(g_DefaultRouteScanStruct == NULL)
							{
								g_DefaultRouteScanStruct = pScanStruct;
							}

							if(g_DefaultRouteScanStruct == pScanStruct)
							{
								if(g_DefaultRouteIp == 0x00000000)
								{
									throw std::exception("Default Route Ip Not Set Or 0.0.0.0");
								}

								pktArpPacketHeader.TargetProtocolAddress = g_DefaultRouteIp;
								RtlFillMemory(&pktEthernetFrameHeader.DestinationMac, 6, 0xFF);
								RtlFillMemory(&pktArpPacketHeader.TargetHardwareAddress, 6, 0xFF);
							}
						}
						else
						{
							pktArpPacketHeader.TargetProtocolAddress = pScanStruct->Ip;
						}

						if(pktArpPacketHeader.TargetProtocolAddress != 0)
						{
							SecureZeroMemory(pktData, pktDataSize);
							RtlCopyMemory(pktData, &pktEthernetFrameHeader, sizeof(EthernetFrameHeader));
							RtlCopyMemory(pktData + sizeof(EthernetFrameHeader), &pktArpPacketHeader, sizeof(ArpPacketHeader));
							
							pktHeader.caplen = pktHeader.len = (sizeof(EthernetFrameHeader) + sizeof(ArpPacketHeader));
							if(pcap_sendqueue_queue(pktSendQueue, &pktHeader, pktData) != 0)
							{
								throw std::exception("pcap_sendqueue_queue() Failed.");
							}

							QueryPerformanceCounter(&pScanStruct->lCounterLastPacketTime);
							currentQueueCount++;
							pScanStruct->Attempt++;
						}
					}
				}
				else
				{
					if((g_uPacketQueueCount - currentQueueCount) < g_uPacketBlockCount)
					{
						break;
					}

					bool bIcmpAttempt = ((g_ScanType & ScanTypeIcmpEcho) ||
										 (g_ScanType & ScanTypeIcmpRouter) ||
										 (g_ScanType & ScanTypeIcmpTimestamp) ||
										 (g_ScanType & ScanTypeIcmpInformation) ||
										 (g_ScanType & ScanTypeIcmpNetmask)) &&
										(pScanStruct->Attempt < g_uPacketAttemptCount);

					bool bIcmpTraceComplete = (pScanStruct->RouteEchoResponseTtl != 0xFFFFFFFF) &&
						                      ((pScanStruct->RouteTtl / g_uPacketAttemptCount) > pScanStruct->RouteEchoResponseTtl);

					bool bTcpTraceComplete = (pScanStruct->RouteTcpResponseTtl != 0xFFFFFFFF) &&
						                     ((pScanStruct->RouteTtl / g_uPacketAttemptCount) > pScanStruct->RouteTcpResponseTtl);

					bool bUdpTraceComplete = (pScanStruct->RouteUdpResponseTtl != 0xFFFFFFFF) &&
						                     ((pScanStruct->RouteTtl / g_uPacketAttemptCount) > pScanStruct->RouteUdpResponseTtl);

					bool bTraceAttempt = ((pScanStruct->RouteTtl / g_uPacketAttemptCount) <= 255) &&
										 (((g_ScanType & ScanTypeIcmpTrace) && !bIcmpTraceComplete) ||
										  ((g_ScanType & ScanTypeTcpTrace) && !bTcpTraceComplete) ||
										  ((g_ScanType & ScanTypeUdpTrace)) && !bUdpTraceComplete);
	
					for(u_int p = 0; ((p < g_uPacketBlockCount) && (bIcmpAttempt || bTraceAttempt)) ;)
					{
						bIcmpAttempt = ((g_ScanType & ScanTypeIcmpEcho) ||
										 (g_ScanType & ScanTypeIcmpRouter) ||
										 (g_ScanType & ScanTypeIcmpTimestamp) ||
										 (g_ScanType & ScanTypeIcmpInformation) ||
										 (g_ScanType & ScanTypeIcmpNetmask)) &&
										(pScanStruct->Attempt < g_uPacketAttemptCount);
						
						pktEthernetFrameHeader.Type = EtherTypeIp;
						RtlCopyMemory(&pktEthernetFrameHeader.DestinationMac, &pScanStruct->Mac, 6);

						SecureZeroMemory(pktData, pktDataSize);
						RtlCopyMemory(pktData, &pktEthernetFrameHeader, sizeof(EthernetFrameHeader));

						pktIpPacketHeader.DestinationAddress = pScanStruct->Ip;
						pktChecksumPseudoHeader.DestinationAddress = pScanStruct->Ip;

						if(bTraceAttempt)
						{
							bTraceAttempt = false;

							if((g_ScanType & ScanTypeIcmpTrace) && !bIcmpTraceComplete)
							{
								pktIpPacketHeader.Identification = htons(g_IpIdentification++);
								pktIpPacketHeader.TimeToLive = static_cast<u_char>(pScanStruct->RouteTtl / g_uPacketAttemptCount);
								pktIpPacketHeader.Crc = 0;
								pktIpPacketHeader.Protocol = IpProtocolIcmp;
								pktIpPacketHeader.TotalLength = htons(sizeof(IpPacketHeader) + sizeof(IcmpPacketHeader) + sizeof(pktBuffer));
								
								u_int ipCrc = 0;
								InitialiseChecksum(ipCrc);
								UpdateChecksum(ipCrc, reinterpret_cast<u_short *>(&pktIpPacketHeader), (sizeof(IpPacketHeader)) / sizeof(u_short));
								pktIpPacketHeader.Crc = FinaliseChecksum(ipCrc);
								RtlCopyMemory(pktData + sizeof(EthernetFrameHeader), &pktIpPacketHeader, sizeof(IpPacketHeader));

								pktIcmpPacketHeader.Checksum = 0;
								pktIcmpPacketHeader.Type = IcmpTypeEchoRequest;
								pktIcmpPacketHeader.Code = 0;
								CryptGenRandom(g_hCryptProv, 2, reinterpret_cast<BYTE *>(&pktIcmpPacketHeader.Id));
								pktIcmpPacketHeader.Sequence = htons(static_cast<u_short>(pktIpPacketHeader.TimeToLive));
								
								u_int icmpChecksum = 0;
								InitialiseChecksum(icmpChecksum);
								UpdateChecksum(icmpChecksum, reinterpret_cast<u_short *>(&pktIcmpPacketHeader), sizeof(IcmpPacketHeader) / sizeof(u_short));
								UpdateChecksum(icmpChecksum, reinterpret_cast<u_short *>(&pktBuffer), sizeof(pktBuffer) / sizeof(u_short));
								pktIcmpPacketHeader.Checksum = FinaliseChecksum(icmpChecksum);

								RtlCopyMemory(pktData + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader), &pktIcmpPacketHeader, sizeof(IcmpPacketHeader));
								RtlCopyMemory(pktData + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader) + sizeof(IcmpPacketHeader), &pktBuffer, sizeof(pktBuffer));

								pktHeader.caplen = pktHeader.len = (sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader) + sizeof(IcmpPacketHeader) + sizeof(pktBuffer));
								if(pcap_sendqueue_queue(pktSendQueue, &pktHeader, pktData) != 0)
								{
									throw std::exception("pcap_sendqueue_queue() Failed.");
								}

								QueryPerformanceCounter(&pScanStruct->lCounterLastPacketTime);
								currentQueueCount++;
								p++;

								if(pScanStruct->IcmpEvents.find(ScanTypeIcmpTrace) == pScanStruct->IcmpEvents.end())
								{
									pScanStruct->IcmpEvents[ScanTypeIcmpTrace] = std::vector<IcmpEventStruct>();
								}

								IcmpEventStruct icmpEvent;
								SecureZeroMemory(&icmpEvent, sizeof(IcmpEventStruct));
								icmpEvent.Id = pktIcmpPacketHeader.Id;
								icmpEvent.Sequence = pktIcmpPacketHeader.Sequence;
								icmpEvent.Ttl = pktIpPacketHeader.TimeToLive;
								QueryPerformanceCounter(&icmpEvent.Transmit);
								icmpEvent.Response.QuadPart = 0xFFFFFFFFFFFFFFFF;
								pScanStruct->IcmpEvents[ScanTypeIcmpTrace].push_back(icmpEvent);
							}
							if((g_ScanType & ScanTypeTcpTrace) && !bTcpTraceComplete)
							{
								pktIpPacketHeader.Identification = htons(g_IpIdentification++);
								pktIpPacketHeader.TimeToLive = static_cast<u_char>(pScanStruct->RouteTtl / g_uPacketAttemptCount);
								pktIpPacketHeader.Crc = 0;
								pktIpPacketHeader.Protocol = IpProtocolTcp;
								pktChecksumPseudoHeader.Protocol = IpProtocolTcp;
								pktIpPacketHeader.TotalLength = htons(sizeof(IpPacketHeader) + sizeof(TcpPacketHeader));
								pktChecksumPseudoHeader.Length = htons(sizeof(TcpPacketHeader));

								u_int ipCrc = 0;
								InitialiseChecksum(ipCrc);
								UpdateChecksum(ipCrc, reinterpret_cast<u_short *>(&pktIpPacketHeader), (sizeof(IpPacketHeader)) / sizeof(u_short));
								pktIpPacketHeader.Crc = FinaliseChecksum(ipCrc);
								RtlCopyMemory(pktData + sizeof(EthernetFrameHeader), &pktIpPacketHeader, sizeof(IpPacketHeader));

								pktTcpPacketHeader.Checksum = 0;
								pktTcpPacketHeader.Flags = TcpFlagSyn;
								pktTcpPacketHeader.SequenceNumber = htonl(pScanStruct->PacketIsnBase);				

								if(g_ScanType & ScanTypeTraceSport)
								{
									pktTcpPacketHeader.SourcePort = g_SourcePort;
									pktTcpPacketHeader.DestinationPort = g_DestinationPort + htons(static_cast<u_short>(pScanStruct->RouteTtl));
								}
								else if(g_ScanType & ScanTypeTraceDport)
								{
									pktTcpPacketHeader.DestinationPort = g_DestinationPort;
									pktTcpPacketHeader.SourcePort = g_SourcePort + htons(static_cast<u_short>(pScanStruct->RouteTtl));
								}

								u_int tcpChecksum = 0;
								InitialiseChecksum(tcpChecksum);
								UpdateChecksum(tcpChecksum, reinterpret_cast<u_short *>(&pktChecksumPseudoHeader), sizeof(ChecksumPseudoHeader) / sizeof(u_short));
								UpdateChecksum(tcpChecksum, reinterpret_cast<u_short *>(&pktTcpPacketHeader), sizeof(TcpPacketHeader) / sizeof(u_short));
								pktTcpPacketHeader.Checksum = FinaliseChecksum(tcpChecksum);

								RtlCopyMemory(pktData + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader), &pktTcpPacketHeader, sizeof(TcpPacketHeader));
								pktHeader.caplen = pktHeader.len = (sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader) + sizeof(TcpPacketHeader));
								if(pcap_sendqueue_queue(pktSendQueue, &pktHeader, pktData) != 0)
								{
									throw std::exception("pcap_sendqueue_queue() Failed.");
								}

								QueryPerformanceCounter(&pScanStruct->lCounterLastPacketTime);
								currentQueueCount++;
								p++;

								if(pScanStruct->IcmpEvents.find(ScanTypeTcpTrace) == pScanStruct->IcmpEvents.end())
								{
									pScanStruct->IcmpEvents[ScanTypeTcpTrace] = std::vector<IcmpEventStruct>();
								}

								IcmpEventStruct icmpEvent;
								SecureZeroMemory(&icmpEvent, sizeof(IcmpEventStruct));
								icmpEvent.Id = pktTcpPacketHeader.SourcePort;
								icmpEvent.Sequence = pktTcpPacketHeader.DestinationPort;
								icmpEvent.Ttl = pktIpPacketHeader.TimeToLive;
								QueryPerformanceCounter(&icmpEvent.Transmit);
								icmpEvent.Response.QuadPart = 0xFFFFFFFFFFFFFFFF;
								pScanStruct->IcmpEvents[ScanTypeTcpTrace].push_back(icmpEvent);
							}
							if((g_ScanType & ScanTypeUdpTrace) && !bUdpTraceComplete)
							{
								pktIpPacketHeader.Identification = htons(g_IpIdentification++);
								pktIpPacketHeader.TimeToLive = static_cast<u_char>(pScanStruct->RouteTtl / g_uPacketAttemptCount);
								pktIpPacketHeader.Crc = 0;
								pktIpPacketHeader.Protocol = IpProtocolUdp;
								pktChecksumPseudoHeader.Protocol = IpProtocolUdp;
								pktIpPacketHeader.TotalLength = htons(sizeof(IpPacketHeader) + sizeof(UdpPacketHeader) + sizeof(pktBuffer));
								pktChecksumPseudoHeader.Length = htons(sizeof(UdpPacketHeader) + sizeof(pktBuffer));

								u_int ipCrc = 0;
								InitialiseChecksum(ipCrc);
								UpdateChecksum(ipCrc, reinterpret_cast<u_short *>(&pktIpPacketHeader), (sizeof(IpPacketHeader)) / sizeof(u_short));
								pktIpPacketHeader.Crc = FinaliseChecksum(ipCrc);
								RtlCopyMemory(pktData + sizeof(EthernetFrameHeader), &pktIpPacketHeader, sizeof(IpPacketHeader));

								pktUdpPacketHeader.Checksum = 0;
								pktUdpPacketHeader.Length = htons(sizeof(UdpPacketHeader) + sizeof(pktBuffer));

								if(g_ScanType & ScanTypeTraceSport)
								{
									pktUdpPacketHeader.SourcePort = g_SourcePort;
									pktUdpPacketHeader.DestinationPort = g_DestinationPort + htons(static_cast<u_short>(pScanStruct->RouteTtl));
								}
								else if(g_ScanType & ScanTypeTraceDport)
								{
									pktUdpPacketHeader.DestinationPort = g_DestinationPort;
									pktUdpPacketHeader.SourcePort = g_SourcePort + htons(static_cast<u_short>(pScanStruct->RouteTtl));
								}

								u_int udpChecksum = 0;
								InitialiseChecksum(udpChecksum);
								UpdateChecksum(udpChecksum, reinterpret_cast<u_short *>(&pktChecksumPseudoHeader), sizeof(ChecksumPseudoHeader) / sizeof(u_short));
								UpdateChecksum(udpChecksum, reinterpret_cast<u_short *>(&pktUdpPacketHeader), sizeof(UdpPacketHeader) / sizeof(u_short));
								UpdateChecksum(udpChecksum, reinterpret_cast<u_short *>(&pktBuffer), sizeof(pktBuffer) / sizeof(u_short));
								pktUdpPacketHeader.Checksum = FinaliseChecksum(udpChecksum);

								RtlCopyMemory(pktData + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader), &pktUdpPacketHeader, sizeof(UdpPacketHeader));
								RtlCopyMemory(pktData + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader) + sizeof(UdpPacketHeader), &pktBuffer, sizeof(pktBuffer));

								pktHeader.caplen = pktHeader.len = (sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader) + sizeof(UdpPacketHeader) + sizeof(pktBuffer));
								if(pcap_sendqueue_queue(pktSendQueue, &pktHeader, pktData) != 0)
								{
									throw std::exception("pcap_sendqueue_queue() Failed.");
								}

								QueryPerformanceCounter(&pScanStruct->lCounterLastPacketTime);
								currentQueueCount++;
								p++;

								if(pScanStruct->IcmpEvents.find(ScanTypeUdpTrace) == pScanStruct->IcmpEvents.end())
								{
									pScanStruct->IcmpEvents[ScanTypeUdpTrace] = std::vector<IcmpEventStruct>();
								}

								IcmpEventStruct icmpEvent;
								SecureZeroMemory(&icmpEvent, sizeof(IcmpEventStruct));
								icmpEvent.Id = pktUdpPacketHeader.SourcePort;
								icmpEvent.Sequence = pktUdpPacketHeader.DestinationPort;
								icmpEvent.Ttl = pktIpPacketHeader.TimeToLive;
								QueryPerformanceCounter(&icmpEvent.Transmit);
								icmpEvent.Response.QuadPart = 0xFFFFFFFFFFFFFFFF;
								pScanStruct->IcmpEvents[ScanTypeUdpTrace].push_back(icmpEvent);
							}

							pScanStruct->RouteTtl++;
						}
						if(bIcmpAttempt && (g_ScanType & ScanTypeIcmpEcho))
						{
							pktIpPacketHeader.Identification = htons(g_IpIdentification++);
							pktIpPacketHeader.TimeToLive = 255;
							pktIpPacketHeader.Crc = 0;
							pktIpPacketHeader.Protocol = IpProtocolIcmp;
							pktIpPacketHeader.TotalLength = htons(sizeof(IpPacketHeader) + sizeof(IcmpPacketHeader) + sizeof(pktBuffer));
							
							u_int ipCrc = 0;
							InitialiseChecksum(ipCrc);
							UpdateChecksum(ipCrc, reinterpret_cast<u_short *>(&pktIpPacketHeader), (sizeof(IpPacketHeader)) / sizeof(u_short));
							pktIpPacketHeader.Crc = FinaliseChecksum(ipCrc);
							RtlCopyMemory(pktData + sizeof(EthernetFrameHeader), &pktIpPacketHeader, sizeof(IpPacketHeader));

							pktIcmpPacketHeader.Checksum = 0;
							pktIcmpPacketHeader.Type = IcmpTypeEchoRequest;
							pktIcmpPacketHeader.Code = 0;
							CryptGenRandom(g_hCryptProv, 2, reinterpret_cast<BYTE *>(&pktIcmpPacketHeader.Id));
							pktIcmpPacketHeader.Sequence = htons(static_cast<u_short>(pScanStruct->Attempt));
							
							u_int icmpChecksum = 0;
							InitialiseChecksum(icmpChecksum);
							UpdateChecksum(icmpChecksum, reinterpret_cast<u_short *>(&pktIcmpPacketHeader), sizeof(IcmpPacketHeader) / sizeof(u_short));
							UpdateChecksum(icmpChecksum, reinterpret_cast<u_short *>(&pktBuffer), sizeof(pktBuffer) / sizeof(u_short));
							pktIcmpPacketHeader.Checksum = FinaliseChecksum(icmpChecksum);

							RtlCopyMemory(pktData + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader), &pktIcmpPacketHeader, sizeof(IcmpPacketHeader));
							RtlCopyMemory(pktData + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader) + sizeof(IcmpPacketHeader), &pktBuffer, sizeof(pktBuffer));

							pktHeader.caplen = pktHeader.len = (sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader) + sizeof(IcmpPacketHeader) + sizeof(pktBuffer));
							if(pcap_sendqueue_queue(pktSendQueue, &pktHeader, pktData) != 0)
							{
								throw std::exception("pcap_sendqueue_queue() Failed.");
							}

							QueryPerformanceCounter(&pScanStruct->lCounterLastPacketTime);
							currentQueueCount++;
							p++;

							if(pScanStruct->IcmpEvents.find(ScanTypeIcmpEcho) == pScanStruct->IcmpEvents.end())
							{
								pScanStruct->IcmpEvents[ScanTypeIcmpEcho] = std::vector<IcmpEventStruct>();
							}

							IcmpEventStruct icmpEvent;
							SecureZeroMemory(&icmpEvent, sizeof(IcmpEventStruct));
							icmpEvent.Id = pktIcmpPacketHeader.Id;
							icmpEvent.Sequence = pktIcmpPacketHeader.Sequence;
							icmpEvent.Ttl = pktIpPacketHeader.TimeToLive;
							QueryPerformanceCounter(&icmpEvent.Transmit);
							icmpEvent.Response.QuadPart = 0xFFFFFFFFFFFFFFFF;
							pScanStruct->IcmpEvents[ScanTypeIcmpEcho].push_back(icmpEvent);
						}
						if(bIcmpAttempt && (g_ScanType & ScanTypeIcmpRouter))
						{
							pktIpPacketHeader.Identification = htons(g_IpIdentification++);
							pktIpPacketHeader.TimeToLive = 255;
							pktIpPacketHeader.Crc = 0;
							pktIpPacketHeader.Protocol = IpProtocolIcmp;
							pktIpPacketHeader.TotalLength = htons(sizeof(IpPacketHeader) + sizeof(IcmpPacketHeader));
							
							u_int ipCrc = 0;
							InitialiseChecksum(ipCrc);
							UpdateChecksum(ipCrc, reinterpret_cast<u_short *>(&pktIpPacketHeader), (sizeof(IpPacketHeader)) / sizeof(u_short));
							pktIpPacketHeader.Crc = FinaliseChecksum(ipCrc);
							RtlCopyMemory(pktData + sizeof(EthernetFrameHeader), &pktIpPacketHeader, sizeof(IpPacketHeader));

							pktIcmpPacketHeader.Checksum = 0;
							pktIcmpPacketHeader.Type = IcmpTypeRouterSolicitation;
							pktIcmpPacketHeader.Code = 0;
							CryptGenRandom(g_hCryptProv, 2, reinterpret_cast<BYTE *>(&pktIcmpPacketHeader.Id));
							pktIcmpPacketHeader.Sequence = htons(static_cast<u_short>(pScanStruct->Attempt));
							
							u_int icmpChecksum = 0;
							InitialiseChecksum(icmpChecksum);
							UpdateChecksum(icmpChecksum, reinterpret_cast<u_short *>(&pktIcmpPacketHeader), sizeof(IcmpPacketHeader) / sizeof(u_short));
							pktIcmpPacketHeader.Checksum = FinaliseChecksum(icmpChecksum);

							RtlCopyMemory(pktData + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader), &pktIcmpPacketHeader, sizeof(IcmpPacketHeader));
							pktHeader.caplen = pktHeader.len = (sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader) + sizeof(IcmpPacketHeader));
							if(pcap_sendqueue_queue(pktSendQueue, &pktHeader, pktData) != 0)
							{
								throw std::exception("pcap_sendqueue_queue() Failed.");
							}

							QueryPerformanceCounter(&pScanStruct->lCounterLastPacketTime);
							currentQueueCount++;
							p++;

							if(pScanStruct->IcmpEvents.find(ScanTypeIcmpRouter) == pScanStruct->IcmpEvents.end())
							{
								pScanStruct->IcmpEvents[ScanTypeIcmpRouter] = std::vector<IcmpEventStruct>();
							}

							IcmpEventStruct icmpEvent;
							SecureZeroMemory(&icmpEvent, sizeof(IcmpEventStruct));
							icmpEvent.Id = pktIcmpPacketHeader.Id;
							icmpEvent.Sequence = pktIcmpPacketHeader.Sequence;
							icmpEvent.Ttl = pktIpPacketHeader.TimeToLive;
							QueryPerformanceCounter(&icmpEvent.Transmit);
							icmpEvent.Response.QuadPart = 0xFFFFFFFFFFFFFFFF;
							pScanStruct->IcmpEvents[ScanTypeIcmpRouter].push_back(icmpEvent);
						}
						if(bIcmpAttempt && (g_ScanType & ScanTypeIcmpTimestamp))
						{
							pktIpPacketHeader.Identification = htons(g_IpIdentification++);
							pktIpPacketHeader.TimeToLive = 255;
							pktIpPacketHeader.Crc = 0;
							pktIpPacketHeader.Protocol = IpProtocolIcmp;
							pktIpPacketHeader.TotalLength = htons(sizeof(IpPacketHeader) + sizeof(IcmpPacketHeader) + 12);
							
							u_int ipCrc = 0;
							InitialiseChecksum(ipCrc);
							UpdateChecksum(ipCrc, reinterpret_cast<u_short *>(&pktIpPacketHeader), (sizeof(IpPacketHeader)) / sizeof(u_short));
							pktIpPacketHeader.Crc = FinaliseChecksum(ipCrc);
							RtlCopyMemory(pktData + sizeof(EthernetFrameHeader), &pktIpPacketHeader, sizeof(IpPacketHeader));

							pktIcmpPacketHeader.Checksum = 0;
							pktIcmpPacketHeader.Type = IcmpTypeTimestampRequest;
							pktIcmpPacketHeader.Code = 0;
							CryptGenRandom(g_hCryptProv, 2, reinterpret_cast<BYTE *>(&pktIcmpPacketHeader.Id));
							pktIcmpPacketHeader.Sequence = htons(static_cast<u_short>(pScanStruct->Attempt));
							
							u_int originateTimestamp = 0x00000000;
							u_int receiveTimestamp = 0x00000000;
							u_int transmitTimestamp = 0x00000000;

							u_int icmpChecksum = 0;
							InitialiseChecksum(icmpChecksum);
							UpdateChecksum(icmpChecksum, reinterpret_cast<u_short *>(&pktIcmpPacketHeader), sizeof(IcmpPacketHeader) / sizeof(u_short));
							UpdateChecksum(icmpChecksum, reinterpret_cast<u_short *>(&originateTimestamp), sizeof(u_int) / sizeof(u_short));
							UpdateChecksum(icmpChecksum, reinterpret_cast<u_short *>(&receiveTimestamp), sizeof(u_int) / sizeof(u_short));
							UpdateChecksum(icmpChecksum, reinterpret_cast<u_short *>(&transmitTimestamp), sizeof(u_int) / sizeof(u_short));
							pktIcmpPacketHeader.Checksum = FinaliseChecksum(icmpChecksum);

							RtlCopyMemory(pktData + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader), &pktIcmpPacketHeader, sizeof(IcmpPacketHeader));
							*reinterpret_cast<u_int *>(pktData + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader) + sizeof(IcmpPacketHeader)) = originateTimestamp;
							*reinterpret_cast<u_int *>(pktData + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader) + sizeof(IcmpPacketHeader) + 4) = receiveTimestamp;
							*reinterpret_cast<u_int *>(pktData + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader) + sizeof(IcmpPacketHeader) + 8) = transmitTimestamp;

							pktHeader.caplen = pktHeader.len = (sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader) + sizeof(IcmpPacketHeader) + 12);
							if(pcap_sendqueue_queue(pktSendQueue, &pktHeader, pktData) != 0)
							{
								throw std::exception("pcap_sendqueue_queue() Failed.");
							}

							QueryPerformanceCounter(&pScanStruct->lCounterLastPacketTime);
							currentQueueCount++;
							p++;

							if(pScanStruct->IcmpEvents.find(ScanTypeIcmpTimestamp) == pScanStruct->IcmpEvents.end())
							{
								pScanStruct->IcmpEvents[ScanTypeIcmpTimestamp] = std::vector<IcmpEventStruct>();
							}

							IcmpEventStruct icmpEvent;
							SecureZeroMemory(&icmpEvent, sizeof(IcmpEventStruct));
							icmpEvent.Id = pktIcmpPacketHeader.Id;
							icmpEvent.Sequence = pktIcmpPacketHeader.Sequence;
							icmpEvent.Ttl = pktIpPacketHeader.TimeToLive;
							QueryPerformanceCounter(&icmpEvent.Transmit);
							icmpEvent.Response.QuadPart = 0xFFFFFFFFFFFFFFFF;
							pScanStruct->IcmpEvents[ScanTypeIcmpTimestamp].push_back(icmpEvent);
						}
						if(bIcmpAttempt && (g_ScanType & ScanTypeIcmpInformation))
						{
							pktIpPacketHeader.Identification = htons(g_IpIdentification++);
							pktIpPacketHeader.TimeToLive = 255;
							pktIpPacketHeader.Crc = 0;
							pktIpPacketHeader.Protocol = IpProtocolIcmp;
							pktIpPacketHeader.TotalLength = htons(sizeof(IpPacketHeader) + sizeof(IcmpPacketHeader));
							
							u_int ipCrc = 0;
							InitialiseChecksum(ipCrc);
							UpdateChecksum(ipCrc, reinterpret_cast<u_short *>(&pktIpPacketHeader), (sizeof(IpPacketHeader)) / sizeof(u_short));
							pktIpPacketHeader.Crc = FinaliseChecksum(ipCrc);
							RtlCopyMemory(pktData + sizeof(EthernetFrameHeader), &pktIpPacketHeader, sizeof(IpPacketHeader));

							pktIcmpPacketHeader.Checksum = 0;
							pktIcmpPacketHeader.Type = IcmpTypeInformationRequest;
							pktIcmpPacketHeader.Code = 0;
							CryptGenRandom(g_hCryptProv, 2, reinterpret_cast<BYTE *>(&pktIcmpPacketHeader.Id));
							pktIcmpPacketHeader.Sequence = htons(static_cast<u_short>(pScanStruct->Attempt));
							
							u_int icmpChecksum = 0;
							InitialiseChecksum(icmpChecksum);
							UpdateChecksum(icmpChecksum, reinterpret_cast<u_short *>(&pktIcmpPacketHeader), sizeof(IcmpPacketHeader) / sizeof(u_short));
							pktIcmpPacketHeader.Checksum = FinaliseChecksum(icmpChecksum);

							RtlCopyMemory(pktData + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader), &pktIcmpPacketHeader, sizeof(IcmpPacketHeader));
							pktHeader.caplen = pktHeader.len = (sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader) + sizeof(IcmpPacketHeader));
							if(pcap_sendqueue_queue(pktSendQueue, &pktHeader, pktData) != 0)
							{
								throw std::exception("pcap_sendqueue_queue() Failed.");
							}

							QueryPerformanceCounter(&pScanStruct->lCounterLastPacketTime);
							currentQueueCount++;
							p++;

							if(pScanStruct->IcmpEvents.find(ScanTypeIcmpInformation) == pScanStruct->IcmpEvents.end())
							{
								pScanStruct->IcmpEvents[ScanTypeIcmpInformation] = std::vector<IcmpEventStruct>();
							}

							IcmpEventStruct icmpEvent;
							SecureZeroMemory(&icmpEvent, sizeof(IcmpEventStruct));
							icmpEvent.Id = pktIcmpPacketHeader.Id;
							icmpEvent.Sequence = pktIcmpPacketHeader.Sequence;
							icmpEvent.Ttl = pktIpPacketHeader.TimeToLive;
							QueryPerformanceCounter(&icmpEvent.Transmit);
							icmpEvent.Response.QuadPart = 0xFFFFFFFFFFFFFFFF;
							pScanStruct->IcmpEvents[ScanTypeIcmpInformation].push_back(icmpEvent);
						}
						if(bIcmpAttempt && (g_ScanType & ScanTypeIcmpNetmask))
						{
							pktIpPacketHeader.Identification = htons(g_IpIdentification++);
							pktIpPacketHeader.TimeToLive = 255;
							pktIpPacketHeader.Crc = 0;
							pktIpPacketHeader.Protocol = IpProtocolIcmp;
							pktIpPacketHeader.TotalLength = htons(sizeof(IpPacketHeader) + sizeof(IcmpPacketHeader) + 4);
							
							u_int ipCrc = 0;
							InitialiseChecksum(ipCrc);
							UpdateChecksum(ipCrc, reinterpret_cast<u_short *>(&pktIpPacketHeader), (sizeof(IpPacketHeader)) / sizeof(u_short));
							pktIpPacketHeader.Crc = FinaliseChecksum(ipCrc);
							RtlCopyMemory(pktData + sizeof(EthernetFrameHeader), &pktIpPacketHeader, sizeof(IpPacketHeader));

							pktIcmpPacketHeader.Checksum = 0;
							pktIcmpPacketHeader.Type = IcmpTypeNetmaskRequest;
							pktIcmpPacketHeader.Code = 0;
							CryptGenRandom(g_hCryptProv, 2, reinterpret_cast<BYTE *>(&pktIcmpPacketHeader.Id));
							pktIcmpPacketHeader.Sequence = htons(static_cast<u_short>(pScanStruct->Attempt));
							
							u_int netmask = 0x00000000;

							u_int icmpChecksum = 0;
							InitialiseChecksum(icmpChecksum);
							UpdateChecksum(icmpChecksum, reinterpret_cast<u_short *>(&pktIcmpPacketHeader), sizeof(IcmpPacketHeader) / sizeof(u_short));
							UpdateChecksum(icmpChecksum, reinterpret_cast<u_short *>(&netmask), sizeof(u_int) / sizeof(u_short));
							pktIcmpPacketHeader.Checksum = FinaliseChecksum(icmpChecksum);

							RtlCopyMemory(pktData + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader), &pktIcmpPacketHeader, sizeof(IcmpPacketHeader));
							*reinterpret_cast<u_int *>(pktData + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader) + sizeof(IcmpPacketHeader)) = netmask;
							pktHeader.caplen = pktHeader.len = (sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader) + sizeof(IcmpPacketHeader) + 4);
							if(pcap_sendqueue_queue(pktSendQueue, &pktHeader, pktData) != 0)
							{
								throw std::exception("pcap_sendqueue_queue() Failed.");
							}

							QueryPerformanceCounter(&pScanStruct->lCounterLastPacketTime);
							currentQueueCount++;
							p++;

							if(pScanStruct->IcmpEvents.find(ScanTypeIcmpNetmask) == pScanStruct->IcmpEvents.end())
							{
								pScanStruct->IcmpEvents[ScanTypeIcmpNetmask] = std::vector<IcmpEventStruct>();
							}

							IcmpEventStruct icmpEvent;
							SecureZeroMemory(&icmpEvent, sizeof(IcmpEventStruct));
							icmpEvent.Id = pktIcmpPacketHeader.Id;
							icmpEvent.Sequence = pktIcmpPacketHeader.Sequence;
							icmpEvent.Ttl = pktIpPacketHeader.TimeToLive;
							QueryPerformanceCounter(&icmpEvent.Transmit);
							icmpEvent.Response.QuadPart = 0xFFFFFFFFFFFFFFFF;
							pScanStruct->IcmpEvents[ScanTypeIcmpNetmask].push_back(icmpEvent);
						}
						pScanStruct->Attempt++;
					}
				}

				if(g_lCounterLastActivity.QuadPart < pScanStruct->lCounterLastPacketTime.QuadPart)
				{
					g_lCounterLastActivity = pScanStruct->lCounterLastPacketTime;
				}
				if(pScanStruct != NULL)
				{
					ReleaseMutex(pScanStruct->hMutex);
					pScanStruct = NULL;
				}

				do
				{
					if(++pScanStructIter == g_ScanStructs.end())
					{
						pScanStructIter = g_ScanStructs.begin();
					}
					
					bool bIcmpAttempt = ((g_ScanType & ScanTypeIcmpEcho) ||
										 (g_ScanType & ScanTypeIcmpTimestamp) ||
										 (g_ScanType & ScanTypeIcmpInformation) ||
										 (g_ScanType & ScanTypeIcmpNetmask)) &&
										(pScanStructIter->second->Attempt < g_uPacketAttemptCount);

					bool bIcmpTraceComplete = (pScanStructIter->second->RouteEchoResponseTtl != 0xFFFFFFFF) &&
						                      ((pScanStructIter->second->RouteTtl / g_uPacketAttemptCount) >= pScanStructIter->second->RouteEchoResponseTtl);

					bool bTcpTraceComplete = (pScanStructIter->second->RouteTcpResponseTtl != 0xFFFFFFFF) &&
						                     ((pScanStructIter->second->RouteTtl / g_uPacketAttemptCount) >= pScanStructIter->second->RouteTcpResponseTtl);

					bool bUdpTraceComplete = (pScanStructIter->second->RouteUdpResponseTtl != 0xFFFFFFFF) &&
						                     ((pScanStructIter->second->RouteTtl / g_uPacketAttemptCount) >= pScanStructIter->second->RouteUdpResponseTtl);
					
					bool bTraceAttempt = ((pScanStructIter->second->RouteTtl / g_uPacketAttemptCount) <= 255) &&
										 (((g_ScanType & ScanTypeIcmpTrace) && !bIcmpTraceComplete) ||
										  ((g_ScanType & ScanTypeTcpTrace) && !bTcpTraceComplete) ||
										  ((g_ScanType & ScanTypeUdpTrace)) && !bUdpTraceComplete);

					if((pScanStructIter == pScanStructLoopIter) ||
					   (bIcmpAttempt || bTraceAttempt))
					{
						break;
					}
				}
				while(true);
				
				if(pScanStructIter == pScanStructLoopIter)
				{
					break;
				}
			}

			if(pktSendQueue != NULL)
			{
				pcap_sendqueue_transmit(g_pAdapter, pktSendQueue, 0);
				pcap_sendqueue_destroy(pktSendQueue);
				pktSendQueue = NULL;
			}
			if(g_uPacketIntervalMs != 0)
			{
				Sleep(g_uPacketIntervalMs);
			}
			QueryPerformanceCounter(&lCounterNow);
		}

		SetEvent(g_hExitEvent);
	}
	catch(const std::exception &e)
	{
		EnterCriticalSection(&g_ConsoleCriticalSection);
		std::cout << "Error: " << e.what() << std::endl;
		LeaveCriticalSection(&g_ConsoleCriticalSection);

		SetEvent(g_hExitEvent);
	}

	if(pScanStruct != NULL)
	{
		ReleaseMutex(pScanStruct->hMutex);
		pScanStruct = NULL;
	}
	if(pktData != NULL)
	{
		delete [] pktData;
		pktData = NULL;
	}
	if(pktSendQueue != NULL)
	{
		pcap_sendqueue_destroy(pktSendQueue);
		pktSendQueue = NULL;
	}

	return 0;
}

// ========================================================================================================================

DWORD CALLBACK ResolveThreadProc(LPVOID lpParameter)
{
	if(g_bResolveHosts)
	{
		while(WaitForSingleObject(g_hExitEvent, 100) != WAIT_OBJECT_0)
		{
			std::queue<u_int> resolveQueue;

			if(WaitForSingleObject(g_hHostNamesMutex, 1000) == WAIT_OBJECT_0)
			{
				for(std::map<u_int, std::string>::iterator i = g_HostNames.begin(); i != g_HostNames.end(); ++i)
				{
					if(i->second == "")
					{
						i->second = "?";
						resolveQueue.push(i->first);
					}
				}
				ReleaseMutex(g_hHostNamesMutex);
			}
			else
			{
				EnterCriticalSection(&g_ConsoleCriticalSection);
				std::cout << "Warning: WaitForSingleObject(g_hHostNamesMutex, 1000) Failed." << std::endl;
				LeaveCriticalSection(&g_ConsoleCriticalSection);
			}

			while(!resolveQueue.empty())
			{
				u_int ip = resolveQueue.front();
				resolveQueue.pop();

				sockaddr_in sockAddrIn;
				SecureZeroMemory(&sockAddrIn, sizeof(sockAddrIn));
				sockAddrIn.sin_addr.S_un.S_addr = ip;
				sockAddrIn.sin_family = AF_INET;
				sockAddrIn.sin_port = 0;

				char nodeName[NI_MAXHOST + 1];
				SecureZeroMemory(&nodeName, sizeof(nodeName));

				std::string hostName;

				if(getnameinfo(reinterpret_cast<const SOCKADDR *>(&sockAddrIn),
							   sizeof(sockAddrIn),
							   reinterpret_cast<PCHAR>(&nodeName),
							   NI_MAXHOST,
							   NULL,
							   0,
							   0) != 0)
				{
					std::stringstream ipBuilder;
					ipBuilder << (ip & 0x000000FF) << "."
							  << ((ip & 0x0000FF00) >> 8) << "."
							  << ((ip & 0x00FF0000) >> 16) << "."
							  << ((ip & 0xFF000000) >> 24);
					hostName = ipBuilder.str();
				}
				else
				{
					hostName = nodeName;
				}

				if(WaitForSingleObject(g_hHostNamesMutex, 1000) == WAIT_OBJECT_0)
				{
					g_HostNames[ip] = hostName;
					ReleaseMutex(g_hHostNamesMutex);
				}
			}
		}
	}

	return 0;
}

// ========================================================================================================================

void GenerateScanStructs(std::string &targetString)
{
	// ------------
	// targetString
	// ------------

	u_int targetBlockMarker = 0;
	while(targetBlockMarker != std::string::npos)
	{
		u_int nextTargetBlockMarker = targetString.find(';', targetBlockMarker + 1);
		std::string targetBlock = targetString.substr(targetBlockMarker + ((targetBlockMarker == 0) ? 0 : 1), nextTargetBlockMarker - targetBlockMarker - ((targetBlockMarker == 0) ? 0 : 1));
		targetBlockMarker = nextTargetBlockMarker;

		for(u_int i = 0; i < targetBlock.size(); ++i)
		{
			if(((targetBlock[i] >= '0') && (targetBlock[i] <= '9')) ||
			   (targetBlock[i] == '.') || (targetBlock[i] == '/') ||
			   (targetBlock[i] == ',') || (targetBlock[i] == '-'))
			{
				continue;
			}

			u_int subnetMaskBitsMarker = targetBlock.find('/');
			std::string hostName = targetBlock.substr(0, subnetMaskBitsMarker);
			std::string subnetString = "";
			if(subnetMaskBitsMarker != std::string::npos)
			{
				subnetString = targetBlock.substr(subnetMaskBitsMarker);
			}

			addrinfo *addrInfoList = NULL;
			if(getaddrinfo(hostName.c_str(), NULL, NULL, &addrInfoList) != 0)
			{
				std::string lookupError = "DNS Lookup for \"";
				lookupError += targetBlock;
				lookupError += "\" Failed.";
				throw std::exception(lookupError.c_str());
			}

			UINT ip = reinterpret_cast<sockaddr_in *>(addrInfoList->ai_addr)->sin_addr.S_un.S_addr;

			std::stringstream ipBuilder;
			ipBuilder << (ip & 0x000000FF) << "."
					  << ((ip & 0x0000FF00) >> 8) << "."
					  << ((ip & 0x00FF0000) >> 16) << "."
					  << ((ip & 0xFF000000) >> 24) << subnetString;
			targetBlock = ipBuilder.str();

			break;
		}

		u_int subnetMaskBitsMarker = targetBlock.find('/');
		u_short subnetMaskBits = 32;
		if(subnetMaskBitsMarker != std::string::npos)
		{
			subnetMaskBits = static_cast<u_short>(strtol(targetBlock.substr(subnetMaskBitsMarker + 1).c_str(), NULL, 10));
			if(subnetMaskBits > 32)
			{
				subnetMaskBits = 32;
			}
			targetBlock = targetBlock.substr(0, subnetMaskBitsMarker);
		}
		
		u_int subnetMask = 0xFFFFFFFF;
		for(u_int i = 0; i < (static_cast<u_int>(32) - subnetMaskBits); ++i)
		{
			subnetMask ^= ((0x01) << i);
		}

		std::string targetOctets[4];
		u_int targetOctetMarker = 0;
		for(u_int i = 0; i < 4; ++i)
		{
			if(targetOctetMarker == std::string::npos)
			{
				throw std::exception("Invalid /Target Specified.");
			}
			u_int nextTargetOctetMarker = targetBlock.find('.', targetOctetMarker + 1);
			targetOctets[i] = targetBlock.substr(targetOctetMarker + ((targetOctetMarker == 0) ? 0 : 1), nextTargetOctetMarker - targetOctetMarker - ((targetOctetMarker == 0) ? 0 : 1));
			targetOctetMarker = nextTargetOctetMarker;

			if(targetOctets[i].empty())
			{
				throw std::exception("Invalid /Target Specified.");
			}
		}

		u_int targetFirstOctetItemMarker = 0;
		while(targetFirstOctetItemMarker != std::string::npos)
		{
			u_int nextTargetFirstOctetItemMarker = targetOctets[0].find(',', targetFirstOctetItemMarker + 1);
			std::string targetFirstOctetItem = targetOctets[0].substr(targetFirstOctetItemMarker + ((targetFirstOctetItemMarker == 0) ? 0 : 1), nextTargetFirstOctetItemMarker - targetFirstOctetItemMarker - ((targetFirstOctetItemMarker == 0) ? 0 : 1));
			targetFirstOctetItemMarker = nextTargetFirstOctetItemMarker;

			u_int targetSecondOctetItemMarker = 0;
			while(targetSecondOctetItemMarker != std::string::npos)
			{
				u_int nextTargetSecondOctetItemMarker = targetOctets[1].find(',', targetSecondOctetItemMarker + 1);
				std::string targetSecondOctetItem = targetOctets[1].substr(targetSecondOctetItemMarker + ((targetSecondOctetItemMarker == 0) ? 0 : 1), nextTargetSecondOctetItemMarker - targetSecondOctetItemMarker - ((targetSecondOctetItemMarker == 0) ? 0 : 1));
				targetSecondOctetItemMarker = nextTargetSecondOctetItemMarker;

				u_int targetThirdOctetItemMarker = 0;
				while(targetThirdOctetItemMarker != std::string::npos)
				{
					u_int nextTargetThirdOctetItemMarker = targetOctets[2].find(',', targetThirdOctetItemMarker + 1);
					std::string targetThirdOctetItem = targetOctets[2].substr(targetThirdOctetItemMarker + ((targetThirdOctetItemMarker == 0) ? 0 : 1), nextTargetThirdOctetItemMarker - targetThirdOctetItemMarker - ((targetThirdOctetItemMarker == 0) ? 0 : 1));
					targetThirdOctetItemMarker = nextTargetThirdOctetItemMarker;

					u_int targetFourthOctetItemMarker = 0;
					while(targetFourthOctetItemMarker != std::string::npos)
					{
						u_int nextTargetFourthOctetItemMarker = targetOctets[3].find(',', targetFourthOctetItemMarker + 1);
						std::string targetFourthOctetItem = targetOctets[3].substr(targetFourthOctetItemMarker + ((targetFourthOctetItemMarker == 0) ? 0 : 1), nextTargetFourthOctetItemMarker - targetFourthOctetItemMarker - ((targetFourthOctetItemMarker == 0) ? 0 : 1));
						targetFourthOctetItemMarker = nextTargetFourthOctetItemMarker;

						std::string ipOctets[4] = {targetFirstOctetItem, targetSecondOctetItem, targetThirdOctetItem, targetFourthOctetItem};
						
						u_int lowIp = 0x00000000;
						u_int highIp = 0x00000000;

						for(u_int i = 0; i < 4; ++i)
						{
							size_t ipOctetRangeMarker = ipOctets[i].find("-");
							if(ipOctetRangeMarker == std::string::npos)
							{
								lowIp |= (strtol(ipOctets[i].c_str(), NULL, 10) << (8 * (3 - i)));
								highIp |= (strtol(ipOctets[i].c_str(), NULL, 10) << (8 * (3 - i)));
							}
							else
							{
								lowIp |= (strtol(ipOctets[i].substr(0, ipOctetRangeMarker).c_str(), NULL, 10) << (8 * (3 - i)));
								highIp |= (strtol(ipOctets[i].substr(ipOctetRangeMarker + 1).c_str(), NULL, 10) << (8 * (3 - i)));
							}
						}

						for(u_int a = ((lowIp & 0xFF000000) >> 24); a <= ((highIp & 0xFF000000) >> 24); ++a)
						{
							for(u_int b = ((lowIp & 0x00FF0000) >> 16); b <= ((highIp & 0x00FF0000) >> 16); ++b)
							{
								for(u_int c = ((lowIp & 0x0000FF00) >> 8); c <= ((highIp & 0x0000FF00) >> 8); ++c)
								{
									for(u_int d = (lowIp & 0x000000FF); d <= (highIp & 0x000000FF); ++d)
									{
										u_int ip = (((a << 24) & 0xFF000000) | ((b << 16) & 0x00FF0000) | ((c << 8) & 0x0000FF00) | (d & 0x000000FF));
										ip &= subnetMask;

										for(u_int i = 0; i < static_cast<u_int>(pow(2.0, 32.0 - subnetMaskBits)); ++i)
										{
											if(((ip | i) == ntohl(g_SourceIp)) || (!g_ScanStructs.empty() && (g_ScanStructs.find(ip | i) != g_ScanStructs.end())))
											{
												continue;
											}

											ScanStruct *pScanStruct = new ScanStruct;
											pScanStruct->Ip = htonl(ip | i);
											g_ScanStructs[(ip | i)] = pScanStruct;

											g_HostNames[pScanStruct->Ip] = "";

											pScanStruct->Attempt = 0;
											pScanStruct->IcmpResponses = 0;
											pScanStruct->RouteTtl = g_uPacketAttemptCount;
											pScanStruct->RouteEchoResponseTtl = 0xFFFFFFFF;
											pScanStruct->RouteTcpResponseTtl = 0xFFFFFFFF;
											pScanStruct->RouteUdpResponseTtl = 0xFFFFFFFF;
											
											pScanStruct->bLocalSubnet = ((ntohl(pScanStruct->Ip) ^ ntohl(g_SourceIp)) & ntohl(g_SourceNetMask)) == 0;
											RtlFillMemory(&pScanStruct->Mac, 6, pScanStruct->bLocalSubnet ? 0xFF : 0x00);
											SecureZeroMemory(&pScanStruct->lCounterLastPacketTime, sizeof(LARGE_INTEGER));

											if((pScanStruct->hMutex = CreateMutex(NULL, FALSE, NULL)) == NULL)
											{
												throw std::exception("CreateMutex() Failed.");
											}
											if(!CryptGenRandom(g_hCryptProv, 4, reinterpret_cast<BYTE *>(&pScanStruct->PacketIsnBase)))
											{
												throw std::exception("CryptGenRandom() Failed.");
											}
											
											if(g_ScanType & ScanTypeDummy)
											{
												EnterCriticalSection(&g_ConsoleCriticalSection);
												std::cout << "SCAN "
														  << ((pScanStruct->Ip & 0x000000FF)) << "."
														  << ((pScanStruct->Ip & 0x0000FF00) >> 8) << "."
														  << ((pScanStruct->Ip & 0x00FF0000) >> 16) << "."
														  << ((pScanStruct->Ip & 0xFF000000) >> 24)
														  << " " << (pScanStruct->bLocalSubnet ? "LOCAL" : "REMOTE")
														  << std::endl;
												LeaveCriticalSection(&g_ConsoleCriticalSection);
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	
	if(g_ScanStructs.size() == 0)
	{
		throw std::exception("No Valid Targets Specified.");
	}
	else if(g_ScanType & ScanTypeDummy)
	{
		throw std::exception("");
	}
}

// ========================================================================================================================

void PrintResults(std::ostream &stream, std::ifstream &inOui)
{
	for(std::map<u_int, ScanStruct *>::iterator i = g_ScanStructs.begin(); i != g_ScanStructs.end(); ++i)
	{
		ScanStruct *pScanStruct = i->second;
		if(((pScanStruct->Mac[0] == 0xFF) &&
			(pScanStruct->Mac[1] == 0xFF) &&
			(pScanStruct->Mac[2] == 0xFF) &&
			(pScanStruct->Mac[3] == 0xFF) &&
			(pScanStruct->Mac[4] == 0xFF) &&
			(pScanStruct->Mac[5] == 0xFF)) ||
		   ((pScanStruct->Mac[0] == 0x00) &&
			(pScanStruct->Mac[1] == 0x00) &&
			(pScanStruct->Mac[2] == 0x00) &&
			(pScanStruct->Mac[3] == 0x00) &&
			(pScanStruct->Mac[4] == 0x00) &&
			(pScanStruct->Mac[5] == 0x00)))
		{
			continue;
		}

		if((!pScanStruct->IcmpEvents.empty()) && (pScanStruct->IcmpResponses != 0))
		{
			if(!g_bResolveHosts)
			{
				stream << ((pScanStruct->Ip & 0x000000FF)) << "."
					   << ((pScanStruct->Ip & 0x0000FF00) >> 8) << "."
					   << ((pScanStruct->Ip & 0x00FF0000) >> 16) << "."
					   << ((pScanStruct->Ip & 0xFF000000) >> 24);
			}
			else
			{
				PrintResultsHostName(stream, pScanStruct->Ip);
			}

			if(pScanStruct->bLocalSubnet)
			{
				stream << " [" << std::hex
					   << std::setfill('0')
					   << std::setw(2) << static_cast<u_short>(pScanStruct->Mac[0]) << ":"
					   << std::setw(2) << static_cast<u_short>(pScanStruct->Mac[1]) << ":"
					   << std::setw(2) << static_cast<u_short>(pScanStruct->Mac[2]) << ":"
					   << std::setw(2) << static_cast<u_short>(pScanStruct->Mac[3]) << ":"
					   << std::setw(2) << static_cast<u_short>(pScanStruct->Mac[4]) << ":"
					   << std::setw(2) << static_cast<u_short>(pScanStruct->Mac[5]) << " / "
					   << std::dec;
				PrintResultsMacVendor(stream, inOui, reinterpret_cast<const u_char *>(&pScanStruct->Mac));
				stream << "]";
			}
			stream << std::endl;

			if(g_ScanType & ScanTypeIcmpEcho)
			{
				stream << "  ICMP ECHO: ";
				PrintResultsIcmpType(stream, pScanStruct->IcmpEvents[ScanTypeIcmpEcho]);
			}
			if(g_ScanType & ScanTypeIcmpRouter)
			{
				stream << "  ICMP ROUTER: ";
				PrintResultsIcmpType(stream, pScanStruct->IcmpEvents[ScanTypeIcmpRouter]);
			}
			if(g_ScanType & ScanTypeIcmpTimestamp)
			{
				stream << "  ICMP TIMESTAMP: ";
				PrintResultsIcmpType(stream, pScanStruct->IcmpEvents[ScanTypeIcmpTimestamp]);
			}
			if(g_ScanType & ScanTypeIcmpInformation)
			{
				stream << "  ICMP INFORMATION: ";
				PrintResultsIcmpType(stream, pScanStruct->IcmpEvents[ScanTypeIcmpInformation]);
			}
			if(g_ScanType & ScanTypeIcmpNetmask)
			{
				stream << "  ICMP NETMASK: ";
				PrintResultsIcmpType(stream, pScanStruct->IcmpEvents[ScanTypeIcmpNetmask]);
			}
			if(g_ScanType & ScanTypeIcmpTrace)
			{
				if((g_ScanType & ScanTypeIcmpEcho) ||
				   (g_ScanType & ScanTypeIcmpRouter) ||
				   (g_ScanType & ScanTypeIcmpTimestamp) ||
				   (g_ScanType & ScanTypeIcmpInformation) ||
				   (g_ScanType & ScanTypeIcmpNetmask))
				{
					stream << std::endl;
				}
				stream << "  ICMP TRACE: ";
				PrintResultsTraceType(stream, pScanStruct->IcmpEvents[ScanTypeIcmpTrace]);
			}
			if(g_ScanType & ScanTypeTcpTrace)
			{
				if((g_ScanType & ScanTypeIcmpEcho) ||
				   (g_ScanType & ScanTypeIcmpRouter) ||
				   (g_ScanType & ScanTypeIcmpTimestamp) ||
				   (g_ScanType & ScanTypeIcmpInformation) ||
				   (g_ScanType & ScanTypeIcmpNetmask) ||
				   (g_ScanType & ScanTypeIcmpTrace))
				{
					stream << std::endl;
				}
				stream << "  TCP TRACE:  ";
				PrintResultsTraceType(stream, pScanStruct->IcmpEvents[ScanTypeTcpTrace]);
			}
			if(g_ScanType & ScanTypeUdpTrace)
			{
				if((g_ScanType & ScanTypeIcmpEcho) ||
				   (g_ScanType & ScanTypeIcmpRouter) ||
				   (g_ScanType & ScanTypeIcmpTimestamp) ||
				   (g_ScanType & ScanTypeIcmpInformation) ||
				   (g_ScanType & ScanTypeIcmpNetmask) ||
				   (g_ScanType & ScanTypeIcmpTrace) ||
				   (g_ScanType & ScanTypeTcpTrace))
				{
					stream << std::endl;
				}
				stream << "  UDP TRACE:  ";
				PrintResultsTraceType(stream, pScanStruct->IcmpEvents[ScanTypeUdpTrace]);
			}
			
			stream << std::endl;
		}
	}
}

// ========================================================================================================================

void PrintResultsIcmpType(std::ostream &stream, std::vector<IcmpEventStruct> &responses)
{
	unsigned __int64 avSum = 0;
	u_int avCount = 0;

	for(std::vector<IcmpEventStruct>::iterator i = responses.begin(); i != responses.end(); ++i)
	{
		unsigned __int64 avValue = ((*i).Response.QuadPart != 0xFFFFFFFFFFFFFFFF) ? (((*i).Response.QuadPart - (*i).Transmit.QuadPart) * 1000 / g_lCounterFrequency.QuadPart) : 0xFFFFFFFFFFFFFFFF;
		
		if(avValue != 0xFFFFFFFFFFFFFFFF)
		{
			stream << avValue << "ms";
		}
		else
		{
			stream << "*";
		}
		stream << (((i + 1) != responses.end()) ? ", " : "");

		if(avValue != 0xFFFFFFFFFFFFFFFF)
		{
			avSum += avValue;
			avCount++;
		}
	}

	stream << " / Av: ";
	if(avCount != 0)
	{
		stream << (avSum / avCount) << "ms";
	}
	else
	{
		stream << "*";
	}
	stream << std::endl;
}

// ========================================================================================================================

void PrintResultsTraceType(std::ostream &stream, std::vector<IcmpEventStruct> &responses)
{
	for(std::vector<IcmpEventStruct>::iterator i = responses.begin(); i != responses.end(); ++i)
	{
		stream << static_cast<u_short>((*i).Ttl);

		std::vector<IcmpEventStruct>::iterator j = i;
		std::vector<IcmpEventStruct>::iterator k = i;
		std::vector<IcmpEventStruct>::iterator l = i;

		while(j != responses.end())
		{
			if((*j).Ttl != (*k).Ttl)
			{
				l = k;
				k = j;
			}
			if(((*j).Ip != 0x00000000) ||
			   ((j + 1) == responses.end()))
			{
				if((j + 1) == responses.end())
				{
					l = k;
				}
				if((*l).Ttl != (*i).Ttl)
				{
					stream << "-" << static_cast<u_short>((*l).Ttl);
				}
				stream << ". ";

				u_int prevIp = 0xFFFFFFFF;
				unsigned __int64 avSum = 0;
				u_int avCount = 0;

				std::vector<IcmpEventStruct>::iterator m = l;
				while((m != responses.end()) && ((*m).Ttl == (*l).Ttl))
				{
					stream << ((m != l) ? ", " : "");

					if(prevIp != (*m).Ip)
					{
						prevIp = (*m).Ip;
						stream << (((*m).Type == IcmpTypeUnreachable) ? "U " : "");
						stream << (((*m).Type == 0xFFFF) ? "TCP " : "");
						stream << (((*m).Type == 0xFFFE) ? "SA " : "");
						stream << (((*m).Type == 0xFFFD) ? "RA " : "");
						if(prevIp != 0x00000000)
						{
							if(!g_bResolveHosts)
							{
								stream << (((*m).Ip & 0x000000FF)) << "."
									   << (((*m).Ip & 0x0000FF00) >> 8) << "."
									   << (((*m).Ip & 0x00FF0000) >> 16) << "."
									   << (((*m).Ip & 0xFF000000) >> 24);
							}
							else
							{
								PrintResultsHostName(stream, (*m).Ip);
							}
						}
						else
						{
							stream << "?.?.?.?";
						}
						stream << ": ";
					}

					unsigned __int64 avValue = ((*m).Response.QuadPart != 0xFFFFFFFFFFFFFFFF) ? (((*m).Response.QuadPart - (*m).Transmit.QuadPart) * 1000 / g_lCounterFrequency.QuadPart) : 0xFFFFFFFFFFFFFFFF;
					if(avValue != 0xFFFFFFFFFFFFFFFF)
					{
						stream << avValue << "ms";
						avSum += avValue;
						avCount++;
					}
					else
					{
						stream << "*";
					}
					++m;
				}
				stream << " / Av ";
				if(avCount != 0)
				{
					stream << (avSum / avCount) << "ms";
				}
				else
				{
					stream << "*";
				}
				stream << std::endl << "              ";
				i = --m;
				break;
			}
			++j;
		}
	}
}

// ========================================================================================================================

void PrintResultsHostName(std::ostream &stream, const u_int ip)
{
	if(g_HostNames.find(ip) != g_HostNames.end())
	{
		stream << g_HostNames[ip];
	}
}

// ========================================================================================================================

void PrintResultsMacVendor(std::ostream &stream, std::ifstream &inOui, const u_char *mac)
{
	std::string vendor = "Unknown";
	if(!inOui.is_open())
	{
		vendor = "Unknown - Missing Oui.dat";
	}
	else
	{
		while(!inOui.eof())
		{
			char lineBuffer[1024];
			inOui.getline(&lineBuffer[0], 1024);

			u_short bytesRead = inOui.gcount();
			lineBuffer[2] = '\0';
			lineBuffer[5] = '\0';
			lineBuffer[8] = '\0';
			if((strtol(reinterpret_cast<char *>(&lineBuffer[0]), NULL, 16) == mac[0]) &&
			   (strtol(reinterpret_cast<char *>(&lineBuffer[3]), NULL, 16) == mac[1]) &&
			   (strtol(reinterpret_cast<char *>(&lineBuffer[6]), NULL, 16) == mac[2]))
			{
				vendor = &lineBuffer[9];
				break;
			}			
		}
		inOui.seekg(0);
	}
	stream << "\"" << vendor << "\"";
}

// ========================================================================================================================

void PrintUsage()
{
	std::cout << "Usage: Scamp.exe /Device <id> /Target <a.b.c-d.e,f,g[/x]> /Resolve" << std::endl
			  << "                 /Icmp <E[cho], R[outer], T[imestamp], I[nformation], N[etmask]>" << std::endl
			  << "                 /Trace <E[cho], T[cp], U[dp]> /Sport <p> /Dport <p>" << std::endl
			  << "                 /Interval <i> /Queue <q> /Block <b> /Retry <r>" << std::endl
			  << "                 /Ip <a.b.c.d> /Netmask <a.b.c.d> /Route <a.b.c.d>" << std::endl
			  << "                 /Output <f> /Dummy /Verbose" << std::endl << std::endl
			  << "Available Devices:" << std::endl << std::endl;

	char pcapErrorBuffer[PCAP_ERRBUF_SIZE];
	pcap_if_t *pDeviceList = NULL;

	if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &pDeviceList, pcapErrorBuffer) == -1)
	{
		std::cout << "Error: pcap_findalldevs_ex() Failed." << std::endl;
	}
	else
	{
		pcap_if_t *pDeviceEnum = pDeviceList;
		int deviceEnumCount = 0;
		while(pDeviceEnum != NULL)
		{
			std::cout << "  " << ++deviceEnumCount << ". " << pDeviceEnum->description << std::endl;
			pDeviceEnum = pDeviceEnum->next;
		}

		if(pDeviceList != NULL)
		{
			pcap_freealldevs(pDeviceList);
			pDeviceList = NULL;
		}
	}
	std::cout << std::endl;
}

// ========================================================================================================================
