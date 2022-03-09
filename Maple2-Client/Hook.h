#pragma once
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers

#include <Windows.h>
#include "detours.h"
#include "SigScanner/sigscanner.h"

namespace hook {
  FARPROC GetFuncAddress(LPCSTR lpLibFileName, LPCSTR lpProcName);
  BOOL SetHook(BOOL bInstall, PVOID* ppvTarget, PVOID pvDetour);

  bool RedirectProcess();
}
