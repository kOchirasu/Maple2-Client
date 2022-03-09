#include <iostream>
#include "hook.h"
#include "config.h"

#define PE_START		0x00401000 /* The standard PE start address */
#define PE_END			0x04FFFFFF /* The scan range of the PE */

namespace hook {
  namespace {
    bool BypassNGS(sigscanner::SigScanner& memory) {
      DWORD dwBypassNGS = memory.FindSig(
        { 0x8D, 0x45, 0xF4, 0x64, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x6A, 0x01 },
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        /*skip=*/1
      ) - 0x1C;

      if (dwBypassNGS == NULL) {
        std::cerr << "BYPASS_NGS failed to find signature." << std::endl;
        return false;
      }

      memory.WriteBytes(dwBypassNGS, { 0x33, 0xC0, 0xC3 }); // return 0
      printf("BYPASS_NGS at %08X\n", dwBypassNGS);
      return true;
    }

    bool DisableNXL(sigscanner::SigScanner& memory) {
      DWORD dwDisableNXL = memory.FindSig(
        { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
          0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0x00, 0x00, 0x00, 0x01, 0x64, 0xA1, 0x00, 0x00, 0x00, 0x00 },
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        /*skip=*/1
      );

      if (dwDisableNXL == NULL) {
        std::cerr << "DISABLE_NXL failed to find signature." << std::endl;
        return false;
      }

      memory.WriteBytes(dwDisableNXL, { 0xB8, 0x00, 0x00, 0x00, 0x00 }); // return 0
      printf("DISABLE_NXL at %08X\n", dwDisableNXL);
      return true;
    }
  }

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

  bool PatchClient() {
    sigscanner::SigScanner memory(PE_START, PE_END);

    bool bResult = true;
    if (config::BypassNGS) {
      bResult &= BypassNGS(memory);
    }

    if (config::DisableNXL) {
      bResult &= DisableNXL(memory);
    }

    return bResult;
  }
}
