#pragma once
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers

#include <Windows.h>
#include "detours.h"
#include "ehdata.h"
#include "SigScanner/sigscanner.h"
#include "dbghelp.h"

#pragma comment(lib, "dbghelp.lib")

namespace hook {
  FARPROC GetFuncAddress(LPCSTR lpLibFileName, LPCSTR lpProcName);

  template<class F>
  F GetVtableFunc(int base, int index) {
    int* addr = (int*)base + index;
    return reinterpret_cast<F>(*(addr));
  }

  BOOL SetHook(BOOL bInstall, PVOID* ppvTarget, PVOID pvDetour);

  bool RedirectProcess();

  bool PatchClient();

  PVOID InterceptExceptions();
}
