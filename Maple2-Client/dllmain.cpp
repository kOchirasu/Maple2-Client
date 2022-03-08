// dllmain.cpp : Defines the entry point for the DLL application.
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#define GLOG_NO_ABBREVIATED_SEVERITIES

#include <Windows.h>
#include "config.h"
#include <glog/logging.h>
#include "nmco_hook.h"
#include "win_hook.h"

#pragma comment(lib, "glog.lib")

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
  switch (dwReason) {
    case DLL_PROCESS_ATTACH:
      DisableThreadLibraryCalls(hModule);
      LOG(INFO) << "Test Info...";
      LOG(ERROR) << "Test Error...";

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
