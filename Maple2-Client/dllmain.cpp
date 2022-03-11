// dllmain.cpp : Defines the entry point for the DLL application.
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#define GLOG_NO_ABBREVIATED_SEVERITIES

#include <Windows.h>
#include <iostream>
#include "config.h"
#include "hook.h"
#include "nmco_hook.h"
#include "win_hook.h"
#include "winsock_hook.h"

#define CLIENT_LOCALE "en-US"

FILE* fpstdout = stdout;
FILE* fpstderr = stderr;

extern "C" __declspec(dllexport)
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
  // Load config file to global variables.
  if (!config::Load("")) {
    MessageBoxA(NULL, "Failed to load config.", "Error", MB_ICONERROR | MB_OK);
    return FALSE;
  }

  switch (dwReason) {
    case DLL_PROCESS_ATTACH:
      DisableThreadLibraryCalls(hModule);

      setlocale(LC_ALL, CLIENT_LOCALE);

      // Redirect the process with custom args.
      if (!hook::RedirectProcess()) {
        MessageBoxA(NULL, "Failed to redirect process.", "Error", MB_ICONERROR | MB_OK);
        return FALSE;
      }

#ifndef _WIN64
      // Intercept and handle exceptions.
      hook::InterceptExceptions();
#endif

      // Create console and attach for logging.
      AllocConsole();
      freopen_s(&fpstdout, "CONOUT$", "w", stdout);
      freopen_s(&fpstderr, "CONOUT$", "w", stderr);

      SetConsoleTitleA(config::WindowName.c_str());
      AttachConsole(GetCurrentProcessId());

      if (!winsock::Hook()) {
        MessageBoxA(NULL, "Failed to hook winsock.", "Error", MB_ICONERROR | MB_OK);
        return FALSE;
      }

      if (!nmco::Hook()) {
        MessageBoxA(NULL, "Failed to hook nmco.", "Error", MB_ICONERROR | MB_OK);
        return FALSE;
      }

      if (!win::Hook()) {
        MessageBoxA(NULL, "Failed to hook window.", "Error", MB_ICONERROR | MB_OK);
        return FALSE;
      }

      std::cout << "Successfully hooked all functions." << std::endl;
      break;
    case DLL_PROCESS_DETACH:
      FreeConsole();
      break;
  }

  return TRUE;
}
