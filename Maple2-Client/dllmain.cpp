// dllmain.cpp : Defines the entry point for the DLL application.
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#define GLOG_NO_ABBREVIATED_SEVERITIES

#include <Windows.h>
#include <iostream>
#include "config.h"
#include "hook.h"
#include "nmco_hook.h"
#include "win_hook.h"

FILE* fpstdout = stdout;
FILE* fpstderr = stderr;

extern "C" __declspec(dllexport)
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
  if (!config::Load("")) {
    MessageBoxA(NULL, "Failed to load config.", "Error", MB_ICONERROR | MB_OK);
    return FALSE;
  }

  switch (dwReason) {
    case DLL_PROCESS_ATTACH:
      DisableThreadLibraryCalls(hModule);
      if (!hook::RedirectProcess()) {
        MessageBoxA(NULL, "Failed to redirect process.", "Error", MB_ICONERROR | MB_OK);
        return FALSE;
      }

      MessageBoxA(NULL, "Message", "Title", MB_ICONERROR | MB_OK);

      AllocConsole();
      freopen_s(&fpstdout, "CONOUT$", "w", stdout);
      freopen_s(&fpstderr, "CONOUT$", "w", stderr);

      SetConsoleTitleA(config::WindowName.c_str());
      AttachConsole(GetCurrentProcessId());

      std::cout << config::HostName << std::endl;
      std::cerr << config::WindowName << std::endl;

      /*if (!win::Hook()) {

      }*/
      break;
    case DLL_PROCESS_DETACH:
      FreeConsole();
      break;
  }

  return TRUE;
}
