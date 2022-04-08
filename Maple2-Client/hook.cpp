#include <iostream>
#include "hook.h"
#include "chat/chat_hook.h"
#include "packet/inpacket_hook.h"
#include "packet/outpacket_hook.h"
#include "config.h"

#define MS_VC_EXCEPTION   0x406D1388

namespace hook {
  namespace {
    bool BypassNGS(sigscanner::SigScanner& memory) {
#ifdef _WIN64
      DWORD_PTR dwBypassNGS = memory.FindSig(
        { 0x48, 0x8D, 0x6C, 0x24, 0xD9, 0x48, 0x81, 0xEC, 0xC0, 0x00, 0x00, 0x00, 0x48, 0xC7, 0x45, 0x07 },{}) - 0x0B;
#else
      DWORD_PTR dwBypassNGS = memory.FindSig(
        { 0x8D, 0x45, 0xF4, 0x64, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x6A, 0x01 }, {}, /*skip=*/1) - 0x1C;
#endif
      if (dwBypassNGS == NULL) {
        std::cerr << "BYPASS_NGS failed to find signature." << std::endl;
        return false;
      }

      memory.WriteBytes(dwBypassNGS, { 0x33, 0xC0, 0xC3 }); // return 0
      std::cout << "BYPASS_NGS at " << (void*)dwBypassNGS << std::endl;
      return true;
    }

    bool DisableNXL(sigscanner::SigScanner& memory) {
#ifdef _WIN64
      DWORD_PTR dwDisableNXL = memory.FindSig(
        { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
          0x48, 0x89, 0x4C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x30, 0x48, 0xC7, 0x44, 0x24, 0x28 }, {});
#else
      DWORD_PTR dwDisableNXL = memory.FindSig(
        { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
          0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0x00, 0x00, 0x00, 0x01, 0x64, 0xA1, 0x00, 0x00, 0x00, 0x00 },
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        /*skip=*/1
      );
#endif

      if (dwDisableNXL == NULL) {
        std::cerr << "DISABLE_NXL failed to find signature." << std::endl;
        return false;
      }

      memory.WriteBytes(dwDisableNXL, { 0xB8, 0x00, 0x00, 0x00, 0x00 }); // return 0
      std::cout << "DISABLE_NXL at " << (void*)dwDisableNXL << std::endl;
      return true;
    }

    bool BypassBanWord(sigscanner::SigScanner& memory) {
      std::string banWord = "banWord.xml";
      std::vector<BYTE> yBanWord(banWord.begin(), banWord.end());
      DWORD_PTR dwBypassBanWord = memory.FindSig(yBanWord, {});

      std::string banWordAll = "banWordAll.xml";
      std::vector<BYTE> yBanWordAll(banWordAll.begin(), banWordAll.end());
      DWORD_PTR dwBypassBanWordAll = memory.FindSig(yBanWordAll, {});

      if (dwBypassBanWord == NULL || dwBypassBanWordAll == NULL) {
        std::cerr << "BYPASS_BANWORD failed to find signature." << std::endl;
        return false;
      }

      if (dwBypassBanWord) {
        memory.WriteBytes(dwBypassBanWord, { '\0' }); // 0-length string
        std::cout << "BYPASS_BANWORD at " << (void*)dwBypassBanWord << std::endl;
      }

      if (dwBypassBanWordAll) {
        memory.WriteBytes(dwBypassBanWordAll, { '\0' }); // 0-length string
        std::cout << "BYPASS_BANWORDALL at " << (void*)dwBypassBanWordAll << std::endl;
      }

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

      if (config::Port < 1024) {
        std::cout << "Unsupported port: " << config::Port << std::endl;
        return false;
      }

      char strCmd[1024];
      std::snprintf(strCmd, 1024, "\"%s\" %d --nxapp=nxl --lc=%s", strFileName, config::Port, config::Locale.c_str());
      std::cout << strCmd << std::endl;

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

    if (config::BypassBanWord) {
      bResult &= BypassBanWord(memory);
    }

#ifndef _WIN64
    if (config::HookChat && !chat::Hook()) {
      MessageBoxA(NULL, "Failed to hook chat.", "Error", MB_ICONERROR | MB_OK);
      return FALSE;
    }

    if (config::HookInPacket && !inpacket::Hook()) {
      MessageBoxA(NULL, "Failed to hook inpacket.", "Error", MB_ICONERROR | MB_OK);
      return FALSE;
    }

    if (config::HookOutPacket && !outpacket::Hook()) {
      MessageBoxA(NULL, "Failed to hook outpacket.", "Error", MB_ICONERROR | MB_OK);
      return FALSE;
    }
#endif

    return bResult;
  }

#ifndef _WIN64
  PVOID InterceptExceptions() {
    PVECTORED_EXCEPTION_HANDLER exHandler = [](EXCEPTION_POINTERS* pExceptionInfo) -> LONG {
      switch (pExceptionInfo->ExceptionRecord->ExceptionCode) {
        case EH_EXCEPTION_NUMBER: { // C++ Exceptions
          if (pExceptionInfo->ExceptionRecord->NumberParameters != EH_EXCEPTION_PARAMETERS) {
            break;
          }

          auto pRec = reinterpret_cast<EHExceptionRecord*>(pExceptionInfo->ExceptionRecord);
          if (pRec->params.magicNumber != EH_MAGIC_NUMBER1) {
            break;
          }

          printf("C++ Exception: %p (Data: %p)\n", pRec->ExceptionAddress, pRec->params.pExceptionObject);
          for (int i = 0; i < pRec->params.pThrowInfo->pCatchableTypeArray->nCatchableTypes; i++) {
            auto type = pRec->params.pThrowInfo->pCatchableTypeArray->arrayOfCatchableTypes[0];
            auto szName = type->pType->name;

            // TODO: MapleStory2 uses MFC and throws abstract CException objects. Handle these!
            // CException objects have a GetErrorMessage() function which means we can log error messages.

            printf("\tException[%d]: %s\n", i, szName);
          }

          _CONTEXT* reg = pExceptionInfo->ContextRecord;
          if (reg) {
            printf("\tEAX=%X EBX=%X ECX=%X EDX=%X EDI=%X ESI=%X EBP=%X EIP=%X ESP=%X\n", reg->Eax, reg->Ebx, reg->Ecx, reg->Edx, reg->Edi, reg->Esi, reg->Ebp, reg->Eip, reg->Esp);
          }
          break;
        }
        case MS_VC_EXCEPTION: // C++ Thread Name Exception
          if (pExceptionInfo->ExceptionRecord->ExceptionAddress != 0) {
            printf("SetThreadName Exception Raised [%p]\n", pExceptionInfo->ExceptionRecord->ExceptionAddress);
          }
          break;
        case STATUS_HEAP_CORRUPTION:
          if (pExceptionInfo->ExceptionRecord->ExceptionAddress != 0) {
            printf("CxxException [STATUS_HEAP_CORRUPTION]: %p\n", pExceptionInfo->ExceptionRecord->ExceptionAddress);
          }
          break;
        case STATUS_ACCESS_VIOLATION:
          if (pExceptionInfo->ExceptionRecord->ExceptionAddress != 0) {
            printf("CxxException [STATUS_ACCESS_VIOLATION]: %p\n", pExceptionInfo->ExceptionRecord->ExceptionAddress);
          }
          break;
        case STATUS_BREAKPOINT:
          if (pExceptionInfo->ExceptionRecord->ExceptionAddress != 0) {
            printf("CxxException [STATUS_BREAKPOINT]: %p\n", pExceptionInfo->ExceptionRecord->ExceptionAddress);
          }
          break;
        case STATUS_PRIVILEGED_INSTRUCTION:
        case DBG_PRINTEXCEPTION_C:
        case DBG_PRINTEXCEPTION_WIDE_C:
          break; // Ignored
        default:
          printf("RegException: %08X (%p)\n", pExceptionInfo->ExceptionRecord->ExceptionCode, pExceptionInfo->ExceptionRecord->ExceptionAddress);
          break;
      }

      return EXCEPTION_CONTINUE_SEARCH;
    };

    return AddVectoredExceptionHandler(1, exHandler);
  }
#endif
}
