#pragma once
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers

#include <Windows.h>
#include <TlHelp32.h>
#include <vector>

namespace sigscanner {
  class SigScanner {
  public:
    SigScanner(DWORD dwStartAddr, DWORD dwEndAddr) : _dwStartAddr(dwStartAddr), _dwEndAddr(dwEndAddr) {}

    template <typename T>
    bool WriteMemory(DWORD dwAddr, T value);

    template <typename T>
    T ReadMemory(DWORD dwAddr);

    DWORD FindSig(const std::vector<BYTE>& sig, const std::vector<bool>& mask, int skip = 0);

    static DWORD FindSig(DWORD dwStart, DWORD dwEnd, const std::vector<BYTE>& sig, const std::vector<bool>& mask, int skip = 0);

  private:
    DWORD _dwStartAddr;
    DWORD _dwEndAddr;
  };
}
