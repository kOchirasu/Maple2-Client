#pragma once
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers

#include <Windows.h>
#include "NMCO\NMGeneral.h"
#include "NMCO\NMSerializable.h"
#include "NMCO\NMFunctionObject.h"

#define BUF_SIZE 2048

namespace nmco {
  typedef BOOL(__cdecl* NMCO_CallNMFunc_t)(int uFuncCode, BYTE* pCallingData, BYTE** ppReturnData, UINT32& uReturnDataLen);

  BOOL Hook();
}
