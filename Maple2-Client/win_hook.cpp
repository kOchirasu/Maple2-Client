#include <string.h>
#include "config.h"
#include "win_hook.h"

namespace win {
  BOOL Hook_CreateWindowExA(BOOL bEnable) {
    static auto _CreateWindowExA = &CreateWindowExA;

    decltype(&CreateWindowExA) Hook = [](DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam) -> HWND {
      if (!config::WindowName.empty() && strcmp(lpClassName, CLIENT_CLASS)) {
        lpWindowName = config::WindowName.c_str();
      }

      return _CreateWindowExA(dwExStyle, lpClassName, lpWindowName, dwStyle, x, y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
    };

    return hook::SetHook(bEnable, reinterpret_cast<void**>(&_CreateWindowExA), Hook);
  }

  BOOL Hook_CreateMutexA(BOOL bEnable) {
    static decltype(&CreateMutexA) _CreateMutexA = &CreateMutexA;

    decltype(&CreateMutexA) Hook = [](LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName) -> HANDLE {
      if (lpName && !strcmp(lpName, MUTLI_MUTEX)) {
        // Initialize Maple2

        if (config::EnableMultiClient) {
          HANDLE hProcHandle = GetCurrentProcess();
          HANDLE hHandle = _CreateMutexA(lpMutexAttributes, bInitialOwner, lpName);
          if (hProcHandle && hHandle) {
            HANDLE hMaple;
            DuplicateHandle(hProcHandle, hHandle, NULL, &hMaple, NULL, FALSE, DUPLICATE_CLOSE_SOURCE);
            CloseHandle(hMaple);
          }

          return hHandle;
        }
      }

      return _CreateMutexA(lpMutexAttributes, bInitialOwner, lpName);
    };

    return hook::SetHook(bEnable, reinterpret_cast<void**>(&_CreateMutexA), Hook);
  }

  BOOL Hook() {
    BOOL bResult = TRUE;
    bResult &= Hook_CreateWindowExA(TRUE);
    bResult &= Hook_CreateMutexA(TRUE);

    return bResult;
  }
}
