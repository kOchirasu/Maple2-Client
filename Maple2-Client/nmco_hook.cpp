#include "hook.h"
#include "nmco_hook.h"

namespace nmco {
  namespace {
    NMCO_CallNMFunc_t _NMCO_CallNMFunc;

    TCHAR g_szUserName[LOGINID_SIZE];
    BYTE* g_pReturnData = new BYTE[BUF_SIZE];

    BOOL SetResponse(CNMSimpleStream& s, BYTE** ppReturnData, UINT32& uReturnDataLen) {
      uReturnDataLen = s.GetBufferSize();
      if (uReturnDataLen > BUF_SIZE) {
        return FALSE;
      }

      memset(g_pReturnData, 0, BUF_SIZE);
      memcpy_s(g_pReturnData, BUF_SIZE, s.GetBufferPtr(), uReturnDataLen);

      *ppReturnData = g_pReturnData;

      return TRUE;
    }
  }

  BOOL __cdecl CallNMFunc(int uFuncCode, BYTE* pCallingData, BYTE** ppReturnData, UINT32& uReturnDataLen) {
    int nEsi = 0;
#ifndef _WIN64
    __asm mov nEsi, esi
#endif

    switch (uFuncCode) {
      case kNMFuncCode_SetLocale:
      case kNMFuncCode_Initialize: {
        CNMSetLocaleFunc retFunc;
        retFunc.bSuccess = true;
        retFunc.SetReturn();

        CNMSimpleStream retStream;
        if (!retFunc.Serialize(retStream)) {
          return FALSE;
        }

        return SetResponse(retStream, ppReturnData, uReturnDataLen);
      }
      case kNMFuncCode_LoginAuth: {
        char* pUserName = reinterpret_cast<LPSTR>(nEsi + 0x001030);
        char* pPassword = reinterpret_cast<LPSTR>(nEsi + 0x001130);
        memcpy_s(g_szUserName, LOGINID_SIZE, pUserName, LOGINID_SIZE);

        CNMLoginAuthFunc retFunc;
        retFunc.bSuccess = true;
        retFunc.nErrorCode = kLoginAuth_OK;
        retFunc.SetReturn();

        CNMSimpleStream retStream;
        if (!retFunc.Serialize(retStream)) {
          return FALSE;
        }

        return SetResponse(retStream, ppReturnData, uReturnDataLen);
      }
      case kNMFuncCode_GetNexonPassport: {
        CNMGetNexonPassportFunc retFunc;
        retFunc.bSuccess = true;
        retFunc.SetReturn();
        _tcscpy_s(retFunc.szNexonPassport, g_szUserName);

        CNMSimpleStream retStream;
        if (!retFunc.Serialize(retStream)) {
          return FALSE;
        }

        return SetResponse(retStream, ppReturnData, uReturnDataLen);
      }
      case kNMFuncCode_LogoutAuth: {
        CNMLogoutAuthFunc retFunc;
        retFunc.bSuccess = true;
        retFunc.SetReturn();

        ZeroMemory(g_szUserName, sizeof(g_szUserName));

        CNMSimpleStream retStream;
        if (!retFunc.Serialize(retStream)) {
          return FALSE;
        }

        return SetResponse(retStream, ppReturnData, uReturnDataLen);
      }
    }

    return _NMCO_CallNMFunc(uFuncCode, pCallingData, ppReturnData, uReturnDataLen);
  }

  BOOL Hook() {
#ifdef _WIN64
    FARPROC nmFuncAddr = hook::GetFuncAddress("NMCOGAME64", "NMCO_CallNMFunction");
#else
    FARPROC nmFuncAddr = hook::GetFuncAddress("NMCOGAME", "NMCO_CallNMFunc");
#endif
    if (!nmFuncAddr) {
      return FALSE;
    }

    _NMCO_CallNMFunc = reinterpret_cast<NMCO_CallNMFunc_t>(nmFuncAddr);
    return hook::SetHook(TRUE, reinterpret_cast<void**>(&_NMCO_CallNMFunc), nmco::CallNMFunc);
  }
}
