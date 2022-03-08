#pragma once
#include <windows.h>

#define BUF_SIZE 2048

namespace nmco {
  typedef BOOL(__cdecl* NMCO_CallNMFunc_t)(int uFuncCode, BYTE* pCallingData, BYTE** ppReturnData, UINT32& uReturnDataLen);
  NMCO_CallNMFunc_t _NMCO_CallNMFunc;

  TCHAR g_szUserName[LOGINID_SIZE];
  BYTE* g_pReturnData = new BYTE[BUF_SIZE];

  BOOL Hook();
}
