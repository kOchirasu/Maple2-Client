#pragma once
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers

#include <Windows.h>
#include <vector>

#ifdef _WIN64
#define PE_START          0x0000000140001000 /* The standard PE start address */
#define PE_END            0x000000014FFFFFFF /* The scan range of the PE */
#else
#define PE_START          0x00401000 /* The standard PE start address */
#define PE_END            0x04FFFFFF /* The scan range of the PE */
#endif

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
