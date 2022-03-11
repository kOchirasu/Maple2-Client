#pragma once
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers

#include <Windows.h>
#include <vector>

namespace sigscanner {
  class SigScanner {
  public:
    SigScanner(DWORD_PTR dwStartAddr, DWORD_PTR dwEndAddr) : _dwStartAddr(dwStartAddr), _dwEndAddr(dwEndAddr) {}

    bool WriteBytes(DWORD_PTR dwAddr, const std::vector<BYTE>& bytes);

    std::vector<BYTE> ReadBytes(DWORD_PTR dwAddr, size_t count);

    DWORD_PTR FindSig(const std::vector<BYTE>& sig, const std::vector<bool>& mask, int skip = 0);

    static DWORD_PTR FindSig(DWORD_PTR dwStart, DWORD_PTR dwEnd, const std::vector<BYTE>& sig, const std::vector<bool>& mask, int skip = 0);

  private:
    DWORD_PTR _dwStartAddr;
    DWORD_PTR _dwEndAddr;
  };
}
