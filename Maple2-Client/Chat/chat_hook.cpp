#include <iostream>
#include "chat_hook.h"
#include "../config.h"
#include "../hook.h"
#include "../SigScanner/sigscanner.h"

#define MS2VisualizerToggle 0x00BA9050

namespace chat {
  namespace { 
    typedef int(__thiscall* thiscallNoParam)(void* ms2);
    int ToggleMS2VisualTrackerManager() {
      return ((thiscallNoParam)MS2VisualizerToggle)(config::MS2VisualTracker);
    }

    void* (__fastcall EncodeChat)(ChatMessage* chat, void* edx, void* packet);
    bool HookChat(sigscanner::SigScanner& memory) {
      DWORD_PTR dwEncodeChat = memory.FindSig(
        { 0x55, 0x8B, 0xEC, 0x56, 0x8B, 0x75, 0x08, 0x8B, 0x06, 0x8B, 0x50, 0x0C, 0x57, 0x8B, 0xF9, 0x8B,
          0x4F, 0x04, 0x51, 0x8B, 0xCE, 0xFF, 0xD2, 0x8B, 0x06, 0x8B, 0x50, 0x20, 0x8D, 0x4F, 0x08, 0x51,
          0x8B, 0xCE, 0xFF, 0xD2, 0x8B, 0x06, 0x8B, 0x50, 0x20, 0x8D, 0x4F, 0x0C, 0x51, 0x8B, 0xCE, 0xFF,
          0xD2, 0x8B, 0x4F, 0x14, 0x8B, 0x06, 0x8B, 0x57, 0x10, 0x8B, 0x40, 0x10, 0x51, 0x52, 0x8B, 0xCE,
          0xFF, 0xD0, 0x5F, 0x5E, 0x5D, 0xC2, 0x04, 0x00 }, {});

      if (dwEncodeChat == NULL) {
        std::cerr << "HOOK_CHAT failed to find signature." << std::endl;
        return false;
      }

      std::cout << "HOOK_CHAT at " << (void*)dwEncodeChat << std::endl;
      static auto _EncodeChat = reinterpret_cast<decltype(&EncodeChat)>(dwEncodeChat);
      decltype(&EncodeChat) Hook = [](ChatMessage* chat, void* edx, void* packet) -> void* {
        if (chat->message != nullptr) {
          std::wstring message(chat->message);
          if (config::EnableVisualizer && message._Equal(L"viz")) {
            ToggleMS2VisualTrackerManager();
          }
        }

        return _EncodeChat(chat, edx, packet);
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_EncodeChat), Hook);
    }
  }

  bool Hook() {
    sigscanner::SigScanner memory(PE_START, PE_END);
    return HookChat(memory);
  }
}
