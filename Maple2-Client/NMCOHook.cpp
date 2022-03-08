#include "Hook.h"
#include "NMCOHook.h"
#include "NMCO\NMGeneral.h"
#include "NMCO\NMSerializable.h"
#include "NMCO\NMFunctionObject.h"

namespace nmco {
  BOOL __cdecl CallNMFunc(int uFuncCode, BYTE* pCallingData, BYTE** ppReturnData, UINT32& uReturnDataLen) {
    int nEsi = 0;
    __asm mov nEsi, esi

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

  BOOL Hook() {
    FARPROC nmFuncAddr = hook::GetFuncAddress("NMCOGAME", "NMCO_CallNMFunc");
    if (!nmFuncAddr) {
      return FALSE;
    }

    _NMCO_CallNMFunc = reinterpret_cast<NMCO_CallNMFunc_t>(nmFuncAddr);
    return hook::SetHook(TRUE, reinterpret_cast<void**>(&_NMCO_CallNMFunc), nmco::CallNMFunc);
  }
}
