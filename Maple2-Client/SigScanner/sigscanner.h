#pragma once
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers

#include <Windows.h>
#include <vector>

namespace sigscanner {
  class SigScanner {
  public:
    SigScanner(DWORD dwStartAddr, DWORD dwEndAddr) : _dwStartAddr(dwStartAddr), _dwEndAddr(dwEndAddr) {}

    bool WriteBytes(DWORD dwAddr, const std::vector<BYTE>& bytes);

    std::vector<BYTE> ReadBytes(DWORD dwAddr, size_t count);

    DWORD FindSig(const std::vector<BYTE>& sig, const std::vector<bool>& mask, int skip = 0);

    static DWORD FindSig(DWORD dwStart, DWORD dwEnd, const std::vector<BYTE>& sig, const std::vector<bool>& mask, int skip = 0);

  private:
    DWORD _dwStartAddr;
    DWORD _dwEndAddr;
  };
}
