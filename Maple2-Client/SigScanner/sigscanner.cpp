#include "sigscanner.h"

namespace sigscanner {
  template <typename T>
  bool SigScanner::WriteMemory(DWORD dwAddr, T value) {
    if (dwAddr < _dwStartAddr || dwAddr + sizeof(T) >= _dwEndAddr) {
      return false;
    }

    *(T*)(dwAddr) = value;
    return true;
  }

  template <typename T>
  T SigScanner::ReadMemory(DWORD dwAddr) {
    if (dwAddr < _dwStartAddr || dwAddr + sizeof(T) >= _dwEndAddr) {
      return NULL;
    }

    return *(T*)dwAddr;
  }

  DWORD SigScanner::FindSig(const std::vector<BYTE>& sig, const std::vector<bool>& mask, int skip) {
    return FindSig(_dwStartAddr, _dwEndAddr, sig, mask, skip);
  }

  DWORD SigScanner::FindSig(DWORD dwStart, DWORD dwEnd, const std::vector<BYTE>& sig, const std::vector<bool>& mask, int skip) {
    if (sig.empty() || sig.size() != mask.size()) {
      return NULL;
    }

    size_t size = sig.size();
    size_t i;
    for (DWORD addr = dwStart; addr < (dwEnd - size); addr++) {
      for (i = 0; i < size; i++) {
        if (mask[i]) {
          continue;
        }

        if (*(BYTE*)(addr + i) != sig[i]) {
          break;
        }
      }

      if (i == size) {
        if (skip > 0) {
          skip--;
        } else {
          return addr;
        }
      }
    }

    return NULL;
  }
}
