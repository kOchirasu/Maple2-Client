#include "sigscanner.h"

namespace sigscanner {
  bool SigScanner::WriteBytes(DWORD_PTR dwAddr, const std::vector<BYTE>& bytes) {
    if (dwAddr < _dwStartAddr || dwAddr + bytes.size() >= _dwEndAddr) {
      return false;
    }

    for (size_t i = 0; i < bytes.size(); i++) {
      *(BYTE*)(dwAddr + i) = bytes[i];
    }
    return true;
  }

  std::vector<BYTE> SigScanner::ReadBytes(DWORD_PTR dwAddr, size_t count) {
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

  DWORD_PTR SigScanner::FindSig(const std::vector<BYTE>& sig, const std::vector<bool>& mask, int skip) {
    return FindSig(_dwStartAddr, _dwEndAddr, sig, mask, 1, skip);
  }

  DWORD_PTR SigScanner::FindSigAligned(const std::vector<BYTE>& sig, const std::vector<bool>& mask, BYTE align, int skip) {
    return FindSig(_dwStartAddr, _dwEndAddr, sig, mask, align, skip);
  }

  DWORD_PTR SigScanner::FindSig(DWORD_PTR dwStart, DWORD_PTR dwEnd, const std::vector<BYTE>& sig, const std::vector<bool>& mask, BYTE align, int skip) {
    if (sig.empty()) {
      return NULL;
    }

    size_t size = sig.size();
    size_t i;
    __try {
      for (DWORD_PTR addr = dwStart; addr < (dwEnd - size); addr += align) {
        for (i = 0; i < size; i++) {
          if (i < mask.size() && mask[i]) {
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
