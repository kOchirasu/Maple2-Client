#include "sigscanner.h"

namespace sigscanner {
  bool SigScanner::WriteBytes(DWORD dwAddr, const std::vector<BYTE>& bytes) {
    if (dwAddr < _dwStartAddr || dwAddr + bytes.size() >= _dwEndAddr) {
      return false;
    }

    for (size_t i = 0; i < bytes.size(); i++) {
      *(BYTE*)(dwAddr + i) = bytes[i];
    }
    return true;
  }

  std::vector<BYTE> SigScanner::ReadBytes(DWORD dwAddr, size_t count) {
    if (dwAddr < _dwStartAddr || dwAddr + count >= _dwEndAddr) {
      return std::vector<BYTE>();
    }

    std::vector<BYTE> result;
    result.reserve(count);
    for (size_t i = 0; i < count; i++) {
      result.push_back(*(BYTE*)(dwAddr + i));
    }

    return result;
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
    __try {
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
          }
          else {
            return addr;
          }
        }
      }
    } __except(EXCEPTION_EXECUTE_HANDLER) { /*Ignored*/ }

    return NULL;
  }
}
