#include <iostream>
#include "hook.h"
#include "chat/chat_hook.h"
#include "packet/inpacket_hook.h"
#include "packet/outpacket_hook.h"
#include "config.h"

#define MS_VC_EXCEPTION   0x406D1388

#define ServiceManagerHook 0x010E6B50
#define NewMS2VisualTracker 0x00BAA7B0

namespace hook {
  namespace {
    bool BypassNGS(sigscanner::SigScanner& memory) {
#ifdef _WIN64
      DWORD_PTR dwBypassNGS = memory.FindSig(
        { 0x48, 0x8D, 0x6C, 0x24, 0xD9, 0x48, 0x81, 0xEC, 0xC0, 0x00, 0x00, 0x00, 0x48, 0xC7, 0x45, 0x07 }, {}) - 0x0B;
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
      const std::string banWord = "banWord.xml";
      std::vector<BYTE> yBanWord(banWord.begin(), banWord.end());
      DWORD_PTR dwBypassBanWord = memory.FindSig(yBanWord, {});

      const std::string banWordAll = "banWordAll.xml";
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

    bool PatchUgdUrl(sigscanner::SigScanner& memory, const std::string& newUrl) {
      const std::string oldUrl = "http://ms2ugcimagetest.s3.amazonaws.com/test/designlab_entry.html";
      std::vector<BYTE> yOldUrl(oldUrl.begin(), oldUrl.end());
      DWORD_PTR dwPatchUgdUrl = memory.FindSig(yOldUrl, {});

      if (dwPatchUgdUrl == NULL) {
        std::cerr << "PATCH_UGD_URL failed to find signature." << std::endl;
        return false;
      }

      std::vector<BYTE> yNewUrl(newUrl.begin(), newUrl.end());
      yNewUrl.push_back('\0'); // Null terminator
      memory.WriteBytes(dwPatchUgdUrl, yNewUrl);
      std::cout << "PATCH_UGD_URL at " << (void*)dwPatchUgdUrl << std::endl;

      // Patch libcef hash check to always succeed. (je -> jmp)
#ifdef _WIN64
      // cf092ef692a2ff18b0fc732b58bde9b8b8655fcc
      memory.WriteBytes(0x141621EA4, { 0xEB });
#else
      // 1572ecbd47bba644fb71ada9451e128cd5087d12
      memory.WriteBytes(0x01523B2B, { 0xEB });
#endif

      // Fix typo on saved fields.
      const std::string startTag = "<dercorations>";
      const std::string fixStartTag = "<decorations>\0";
      std::vector<BYTE> yStartTag(startTag.begin(), startTag.end());
      std::vector<BYTE> yFixStartTag(fixStartTag.begin(), fixStartTag.end());
      DWORD_PTR dwStartTag = memory.FindSig(yStartTag, {});
      memory.WriteBytes(dwStartTag, yFixStartTag);

      const std::string endTag = "</dercorations>";
      const std::string fixEndTag = "</decorations>\0";
      std::vector<BYTE> yEndTag(endTag.begin(), endTag.end());
      std::vector<BYTE> yFixEndTag(fixEndTag.begin(), fixEndTag.end());
      DWORD_PTR dwEndTag = memory.FindSig(yEndTag, {});
      memory.WriteBytes(dwEndTag, yFixEndTag);

      return true;
    }

    void* (__fastcall Initializing)(void* self, void* edx, DWORD* serviceManager, void* a1);
    static auto _Initializing = reinterpret_cast<decltype(&Initializing)>(ServiceManagerHook);

    typedef void* (__thiscall* NewMS2Visualizer)(void* ms2);
    typedef void* (__thiscall* RegisterSystemService)(void* serviceManager, void* service, int priority);

    bool HookServiceManager() {
      decltype(&Initializing) Hook = [](void* self, void* edx, DWORD* serviceManager, void* a1) -> void* {
        void* result = _Initializing(self, edx, serviceManager, a1);

        config::ServiceManager = serviceManager;
        // new MS2TrackerVisualizerManager();
        config::MS2VisualTracker = (DWORD*)std::malloc(0x1B4);
        auto newMs2VisualTracker = (NewMS2Visualizer)NewMS2VisualTracker;
        if (newMs2VisualTracker(config::MS2VisualTracker)) {
          // ServiceManager::RegisterSystemService(...);
          auto registerSystemService = (RegisterSystemService)(*(DWORD*)(*config::ServiceManager + 40));
          registerSystemService(serviceManager, config::MS2VisualTracker, 0x7FFFFFFF);
        }

        return result;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_Initializing), Hook);
    }

    bool (__fastcall IsConfigFile)(void* self, void* edx, char* path);
    static auto _IsConfigFile = reinterpret_cast<decltype(&IsConfigFile)>(0x004B8BC0);

    bool HookIsConfigFile() {
      decltype(&IsConfigFile) Hook = [](void* self, void* edx, char* path) -> bool {
        bool result = _IsConfigFile(self, edx, path);
        // Treat files being loaded from a drive (e.g. C:/) as valid
        // needed for UGD map loading.
        if (path[1] == ':') {
          std::cout << "Loading file: " << path << std::endl;
          return true;
        }

        return result;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_IsConfigFile), Hook);
    }

    typedef int(__cdecl* CefBrowserHostCreateBrowserFn)(int param_1, uintptr_t* param_2, int param_3, uintptr_t* param_4, uintptr_t* param_5);

    static CefBrowserHostCreateBrowserFn _OriginalCefBrowserCreate = nullptr;

    typedef enum {
      STATE_DEFAULT = 0,
      STATE_ENABLED,
      STATE_DISABLED,
    } cef_state_t;

    typedef struct _cef_browser_settings_t {
      size_t size;
      int windowless_frame_rate;
      uintptr_t standard_font_family;
      uintptr_t fixed_font_family;
      uintptr_t serif_font_family;
      uintptr_t sans_serif_font_family;
      uintptr_t cursive_font_family;
      uintptr_t fantasy_font_family;
      int default_font_size;
      int default_fixed_font_size;
      int minimum_font_size;
      int minimum_logical_font_size;

      uintptr_t default_encoding;
      cef_state_t remote_fonts;
      cef_state_t javascript;
    } cef_browser_settings_t;

    static bool HookedCreateBrowser(int param_1, uintptr_t* param_2, int param_3, uintptr_t* param_4,
      uintptr_t* param_5) {
      _cef_browser_settings_t* settings = reinterpret_cast<_cef_browser_settings_t*>(*(param_4 + 8));
      settings->javascript = STATE_ENABLED;

      return _OriginalCefBrowserCreate(param_1, param_2, param_3, param_4, param_5);
    }

   bool EnableCefHook(sigscanner::SigScanner& memory) {
      std::vector<BYTE> pattern = {
        0x48, 0x8B, 0xC4, 0x48, 0x89, 0x50, 0x00, 0x55, 0x56, 0x57, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x00, 0x48, 0xC7, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x58, 0x00, 0x49, 0x8B, 0xD8
      };

      std::vector<bool> mask = {
        true, true, true, false, true, true, true, false, false, false, false, false, true, true, true, false, true, true, true, true, true, true, true, true, true, true, false, true, true, true, true, true, true
      };

      // Find the signature - simplifying by using a shorter but unique portion
      _OriginalCefBrowserCreate = reinterpret_cast<CefBrowserHostCreateBrowserFn> (memory.FindSig(pattern, mask));

      if (_OriginalCefBrowserCreate == NULL) {
        std::cerr << "ENABLE_JS failed to find CEF imports signature." << std::endl;
        return false;
      }

     return hook::SetHook(TRUE, reinterpret_cast<void**>(&_OriginalCefBrowserCreate), HookedCreateBrowser);
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

    if (!config::UgdUrl.empty()) {
      bResult &= PatchUgdUrl(memory, config::UgdUrl);
    }

    if (config::EnableCefHook) {
      bResult &= EnableCefHook(memory);
    }

#ifndef _WIN64
    if (config::EnableVisualizer) {
      if (!chat::Hook()) {
        MessageBoxA(NULL, "Failed to hook chat.", "Error", MB_ICONERROR | MB_OK);
        return FALSE;
      }

      bResult &= HookServiceManager();
    }

    if (!config::UgdUrl.empty()) {
      bResult &= HookIsConfigFile();
    }

    if (config::HookInPacket && !packet::HookIn()) {
      MessageBoxA(NULL, "Failed to hook inpacket.", "Error", MB_ICONERROR | MB_OK);
      return FALSE;
    }

    if (config::HookOutPacket && !packet::HookOut()) {
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
