#define GLOG_NO_ABBREVIATED_SEVERITIES
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <WinSock2.h>
#include <WS2spi.h>
#include <iostream>
#include "config.h"
#include "hook.h"
#include "winsock_hook.h"

#pragma comment(lib, "Ws2_32.lib")

#define NEXON_IP_NA		L"23.98.21"  /* Nexon's North America IP pattern to search for upon hook */
#define NEXON_IP_SA		L"52.171.48" /* Nexon's South America IP pattern to search for upon hook */
#define NEXON_IP_EU		L"13.65.17"  /* Nexon's Europe IP pattern to search for upon hook */
#define NULL_IP         L"0.0.0.0"   /* An uninitialized IP argument presents a "null" IP of zero */

namespace winsock {
  namespace {
    WSPPROC_TABLE g_ProcTable;
    ULONG g_HostAddress;
    ULONG g_RouteAddress;

    /* Hooks the Winsock Service Provider's Connect function to redirect the host to a new socket */
    int WINAPI WSPConnect_Hook(SOCKET s, const struct sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS, LPINT lpErrno) {
      sockaddr_in* service = (sockaddr_in*)name;
      unsigned short pPort = htons(service->sin_port);

      // Retrieve a string buffer of the current socket address (IP)
      WCHAR szAddr[50];
      DWORD dwLen = 50;
      int nRet = WSAAddressToStringW((sockaddr*)name, namelen, NULL, szAddr, &dwLen);
      if (nRet) {
        if (!pPort) {
          std::cerr << "WSAAddressToStringA failed with error: " << nRet << std::endl;
          return nRet;
        }

        std::cout << "Socket redirection falling back to " << config::HostName << std::endl;
      }

      if (wcsstr(szAddr, NEXON_IP_NA) || wcsstr(szAddr, NEXON_IP_SA) || wcsstr(szAddr, NEXON_IP_EU) || wcsstr(szAddr, NULL_IP)) {
        std::cout << "Redirecting from: " << szAddr << std::endl;
        hostent* he = gethostbyname(config::HostName.c_str()); // Resolve DNS
        if (!he) {
          int nRet = WSAGetLastError();
          std::cerr << "Unable to resolve " << config::HostName << " with error: " << nRet << std::endl;
          return nRet;
        }

        std::cout << config::HostName << " resolved to " << he->h_addr_list[0] << std::endl;
        g_RouteAddress = inet_addr(he->h_addr_list[0]);
        g_HostAddress = service->sin_addr.S_un.S_addr;
        service->sin_addr.S_un.S_addr = g_RouteAddress;
      }

      std::cout << "Connecting to " << inet_ntoa(service->sin_addr) << std::endl;
      return g_ProcTable.lpWSPConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS, lpErrno);
    }

    /* Hooks the Winsock Service Provider's GetPeerName function to pretend to be connected to the host */
    int WINAPI WSPGetPeerName_Hook(SOCKET s, sockaddr* name, LPINT namelen, LPINT lpErrno) {
      int nRet = g_ProcTable.lpWSPGetPeerName(s, name, namelen, lpErrno);
      if (nRet == SOCKET_ERROR) {
        std::cerr << "WSPGetPeerName failed with error: " << *lpErrno << std::endl;
        return nRet;
      }

      sockaddr_in* service = reinterpret_cast<sockaddr_in*>(name);
      // Check if the returned address is the routed address
      if (service->sin_addr.S_un.S_addr == g_HostAddress) {
        // Return the socket address back to the host address
        service->sin_addr.S_un.S_addr = g_RouteAddress;
      }

      return 0;
    }
  }

  BOOL Hook() {
    static decltype(&WSPStartup) _WSPStartup = decltype(&WSPStartup)(hook::GetFuncAddress("MSWSOCK", "WSPStartup"));

    decltype(&WSPStartup) Hook = [](WORD wVersionRequested, LPWSPDATA lpWSPData, LPWSAPROTOCOL_INFOW lpProtocolInfo, WSPUPCALLTABLE UpcallTable, LPWSPPROC_TABLE lpProcTable) -> int {
      int ret = _WSPStartup(wVersionRequested, lpWSPData, lpProtocolInfo, UpcallTable, lpProcTable);
      g_ProcTable = *lpProcTable;

      lpProcTable->lpWSPConnect = WSPConnect_Hook;
      lpProcTable->lpWSPGetPeerName = WSPGetPeerName_Hook;

      return ret;
    };

    return hook::SetHook(TRUE, reinterpret_cast<void**>(&_WSPStartup), Hook);
  }
}
