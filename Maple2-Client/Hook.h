#pragma once
#include <Windows.h>
#include "detours.h"

namespace hook {
  FARPROC GetFuncAddress(LPCSTR lpLibFileName, LPCSTR lpProcName);
  BOOL SetHook(BOOL bInstall, PVOID* ppvTarget, PVOID pvDetour);
}
