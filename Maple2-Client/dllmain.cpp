// dllmain.cpp : Defines the entry point for the DLL application.
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers

#include <Windows.h>
#include "config.h"
#include "nmco_hook.h"
#include "win_hook.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
  switch (dwReason) {
    case DLL_PROCESS_ATTACH:
      DisableThreadLibraryCalls(hModule);
      if (!config::Load("")) {

      }

      if (!win::Hook()) {

      }
      break;
    case DLL_PROCESS_DETACH:
      FreeConsole();
      break;
  }

  return TRUE;
}
