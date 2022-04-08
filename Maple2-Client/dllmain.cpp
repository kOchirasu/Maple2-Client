// dllmain.cpp : Defines the entry point for the DLL application.
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers

#include <Windows.h>
#include <iostream>
#include "config.h"
#include "hook.h"
#include "win_hook.h"
#include "winsock_hook.h"

constexpr char CLIENT_LOCALE[] = "en-US";
FILE* fpstdout = stdout;
FILE* fpstderr = stderr;

extern "C" __declspec(dllexport)
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
  switch (dwReason) {
    case DLL_PROCESS_ATTACH:
      DisableThreadLibraryCalls(hModule);

      setlocale(LC_ALL, CLIENT_LOCALE);

      if (AllocConsole()) {
        AttachConsole(GetCurrentProcessId());
        ShowWindow(GetConsoleWindow(), SW_HIDE);

        // Disable QUICK_EDIT_MODE (this can cause the window to freeze)
        DWORD prev_mode;
        HANDLE hConsole = GetStdHandle(STD_INPUT_HANDLE);
        GetConsoleMode(hConsole, &prev_mode);
        SetConsoleMode(hConsole, prev_mode & ~ENABLE_QUICK_EDIT_MODE);

        // Redirect output streams
        freopen_s(&fpstdout, "CONOUT$", "w", stdout);
        freopen_s(&fpstderr, "CONOUT$", "w", stderr);
      }

      // Load config file to global variables.
      if (!config::Load("maple2.ini")) {
        ShowWindow(GetConsoleWindow(), SW_RESTORE);
        MessageBoxA(NULL, "Failed to load config.", "Error", MB_ICONERROR | MB_OK);
        return FALSE;
      }

      // Redirect the process with custom args.
      if (!hook::RedirectProcess()) {
        ShowWindow(GetConsoleWindow(), SW_RESTORE);
        MessageBoxA(NULL, "Failed to redirect process.", "Error", MB_ICONERROR | MB_OK);
        return FALSE;
      }

#ifndef _WIN64
      if (config::LogExceptions) {
        std::cout << "Logging exceptions." << std::endl;
        // Intercept and handle exceptions.
        hook::InterceptExceptions();
      }
#endif

      SetConsoleTitleA(config::WindowName.c_str());
      ShowWindow(GetConsoleWindow(), SW_RESTORE);

      if (!winsock::Hook()) {
        MessageBoxA(NULL, "Failed to hook winsock.", "Error", MB_ICONERROR | MB_OK);
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
