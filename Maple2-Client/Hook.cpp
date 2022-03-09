#include "hook.h"
#include "config.h"

namespace hook {
  FARPROC GetFuncAddress(LPCSTR lpLibFileName, LPCSTR lpProcName) {
    HMODULE hModule = LoadLibraryA(lpLibFileName);
    if (!hModule) {
      return FALSE;
    }

    FARPROC funcAddress = GetProcAddress(hModule, lpProcName);
    if (!funcAddress) {
      return FALSE;
    }

    return funcAddress;
  }

  BOOL SetHook(BOOL bInstall, PVOID* ppvTarget, PVOID pvDetour) {
    if (DetourTransactionBegin() != NO_ERROR) {
      return FALSE;
    }

    auto threadId = GetCurrentThread();
    if (DetourUpdateThread(threadId) == NO_ERROR) {
      auto func = bInstall ? DetourAttach : DetourDetach;

      if (func(ppvTarget, pvDetour) == NO_ERROR) {
        if (DetourTransactionCommit() == NO_ERROR) {
          return TRUE;
        }
      }
    }

    DetourTransactionAbort();
    return FALSE;
  }

  bool RedirectProcess() {
    LPSTR sCmd = GetCommandLineA();

    // We only want to redirect the initial run.
    if (!strstr(sCmd, "nxapp")) {
      char strFileName[MAX_PATH];
      GetModuleFileNameA(NULL, strFileName, MAX_PATH);

      char strCmd[1024];
      std::snprintf(strCmd, 1024, "\"%s\" %d --nxapp=nxl --lc=%s", strFileName, config::Port, config::Locale.c_str());

      PROCESS_INFORMATION procInfo = {};
      STARTUPINFOA startInfo = {};
      if (CreateProcessA(strFileName, strCmd, NULL, NULL, 0, 0, NULL, NULL, &startInfo, &procInfo)) {
        Sleep(10);//Open in current window handle
        exit(EXIT_SUCCESS);//Exit this process so it doesn't redirect
        WaitForSingleObject(procInfo.hProcess, INFINITE);
        CloseHandle(procInfo.hProcess);
        CloseHandle(procInfo.hThread);
        return true;
      }

      return false;
    }

    return true;
  }
}
