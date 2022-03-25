#include "atlstr.h"
#include <iostream>
#include <map>
#include <mutex>
#include "../hook.h"
#include "inpacket_hook.h";

#define CInPacket_init    0x005E2730
#define CInPacket_vtable  0x01809CBC

namespace inpacket {
  namespace {
#pragma region Definitions
    // __thiscall becomes __fastcall with edx as 2nd param.
    __int16(__fastcall Init)(int* packet_base, void* edx);
    static auto _Init = reinterpret_cast<decltype(&Init)>(CInPacket_init);

    bool(__fastcall DecodeB)(void* packet, void* edx);
    static auto _DecodeB = hook::GetVtableFunc<decltype(&DecodeB)>(CInPacket_vtable, 0);

    __int8(__fastcall Decode1)(void* packet, void* edx);
    static auto _Decode1 = hook::GetVtableFunc<decltype(&Decode1)>(CInPacket_vtable, 1);

    __int16(__fastcall Decode2)(void* packet, void* edx);
    static auto _Decode2 = hook::GetVtableFunc<decltype(&Decode2)>(CInPacket_vtable, 2);

    __int32(__fastcall Decode4)(void* packet, void* edx);
    static auto _Decode4 = hook::GetVtableFunc<decltype(&Decode4)>(CInPacket_vtable, 3);

    __int64(__fastcall Decode8)(void* packet, void* edx);
    static auto _Decode8 = hook::GetVtableFunc<decltype(&Decode8)>(CInPacket_vtable, 4);

    float(__fastcall DecodeF)(void* packet, void* edx);
    static auto _DecodeF = hook::GetVtableFunc<decltype(&DecodeF)>(CInPacket_vtable, 5);

    CStringA* (__fastcall DecodeWStrA)(void* packet, void* edx, CStringA* dst);
    static auto _DecodeWStrA = hook::GetVtableFunc<decltype(&DecodeWStrA)>(CInPacket_vtable, 6);

    CStringA* (__fastcall DecodeStrA)(void* packet, void* edx, CStringA* dst);
    static auto _DecodeStrA = hook::GetVtableFunc<decltype(&DecodeStrA)>(CInPacket_vtable, 7);

    CStringW* (__fastcall DecodeStrW)(void* packet, void* edx, CStringW* dst);
    static auto _DecodeStrW = hook::GetVtableFunc<decltype(&DecodeStrW)>(CInPacket_vtable, 8);

    void* (__fastcall DecodeBuf)(void* packet, void* edx, void* dst, size_t size);
    static auto _DecodeBuf = hook::GetVtableFunc<decltype(&DecodeBuf)>(CInPacket_vtable, 9);

    float* (__fastcall DecodeCoordF)(void* packet, void* edx, float* dst);
    static auto _DecodeCoordF = hook::GetVtableFunc<decltype(&DecodeCoordF)>(CInPacket_vtable, 10);

    __int16* (__fastcall DecodeCoordS)(void* packet, void* edx, __int16* dst);
    static auto _DecodeCoordS = hook::GetVtableFunc<decltype(&DecodeCoordS)>(CInPacket_vtable, 11);

    // float (__fastcall Decode2ft10)(void* packet, void* edx);
    // float (__fastcall Decode2ft100)(void* packet, void* edx);
    // float (__fastcall Decode2ftx)(void* packet, void* edx, float mul);
    // float (__fastcall Decode2fd10)(void* packet, void* edx);
    // float (__fastcall Decode2fdx)(void* packet, void* edx, float div);
#pragma endregion

    // These mutexes are used to prevent the same value from being logged in multiple functions.
    static std::map<void*, std::mutex> logMutex;

    bool Init_Hook() {
      decltype(&Init) Hook = [](int* packet_base, void* edx) -> __int16 {
        void* key = static_cast<void*>(packet_base + 1);
        if (!logMutex[key].try_lock()) {
          return _Init(packet_base, edx);
        }

        __int16 opcode = _Init(packet_base, edx);
        printf("[%p]InitIn(%p)=%04X\n", _ReturnAddress(), packet_base+1, opcode);
        logMutex.erase(key);
        return opcode;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_Init), Hook);
    }

    bool Decode1_Hook() {
      decltype(&Decode1) Hook = [](void* packet, void* edx) -> __int8 {
        if (!logMutex[packet].try_lock()) {
          return _Decode1(packet, edx);
        }

        __int8 result = _Decode1(packet, edx);
        printf("[%p]Decode1()=%d\n", _ReturnAddress(), result);
        logMutex.erase(packet);
        return result;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_Decode1), Hook);
    }

    bool Decode2_Hook() {
      decltype(&Decode2) Hook = [](void* packet, void* edx) -> __int16 {
        if (!logMutex[packet].try_lock()) {
          return _Decode2(packet, edx);
        }

        __int16 result = _Decode2(packet, edx);
        printf("[%p]Decode2(%p)=%d\n", _ReturnAddress(), packet, result);
        logMutex.erase(packet);
        return result;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_Decode2), Hook);
    }

    bool Decode4_Hook() {
      decltype(&Decode4) Hook = [](void* packet, void* edx) -> __int32 {
        __int32 result = _Decode4(packet, edx);
        printf("[%p]Decode4()=%d\n", _ReturnAddress(), result);
        return result;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_Decode4), Hook);
    }

    bool Decode8_Hook() {
      decltype(&Decode8) Hook = [](void* packet, void* edx) -> __int64 {
        __int64 result = _Decode8(packet, edx);
        printf("[%p]Decode8()=%lld\n", _ReturnAddress(), result);
        return result;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_Decode8), Hook);
    }

    bool DecodeF_Hook() {
      decltype(&DecodeF) Hook = [](void* packet, void* edx) -> float {
        if (!logMutex[packet].try_lock()) {
          return _DecodeF(packet, edx);
        }

        float result = _DecodeF(packet, edx);
        printf("[%p]DecodeF()=%f\n", _ReturnAddress(), result);
        logMutex.erase(packet);
        return result;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_DecodeF), Hook);
    }

    bool DecodeWStrA_Hook() {
      decltype(&DecodeWStrA) Hook = [](void* packet, void* edx, CStringA* dst) -> CStringA* {
        if (!logMutex[packet].try_lock()) {
          return _DecodeWStrA(packet, edx, dst);
        }

        CStringA* result = _DecodeWStrA(packet, edx, dst);
        printf("[%p]DecodeWStrA()=\"%s\"\n", _ReturnAddress(), result->GetString());
        logMutex.erase(packet);
        return result;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_DecodeWStrA), Hook);
    }

    bool DecodeStrA_Hook() {
      decltype(&DecodeStrA) Hook = [](void* packet, void* edx, CStringA* dst) -> CStringA* {
        if (!logMutex[packet].try_lock()) {
          return _DecodeStrA(packet, edx, dst);
        }

        CStringA* result = _DecodeStrA(packet, edx, dst);
        printf("[%p]DecodeStrA()=\"%s\"\n", _ReturnAddress(), result->GetString());
        logMutex.erase(packet);
        return result;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_DecodeStrA), Hook);
    }

    bool DecodeStrW_Hook() {
      decltype(&DecodeStrW) Hook = [](void* packet, void* edx, CStringW* dst) -> CStringW* {
        if (!logMutex[packet].try_lock()) {
          return _DecodeStrW(packet, edx, dst);
        }

        CStringW* result = _DecodeStrW(packet, edx, dst);
        printf("[%p]DecodeStrW()=\"%ls\"\n", _ReturnAddress(), result->GetString());
        logMutex.erase(packet);
        return result;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_DecodeStrW), Hook);
    }

    bool DecodeBuf_Hook() {
      decltype(&DecodeBuf) Hook = [](void* packet, void* edx, void* dst, size_t size) -> void* {
        void* result = _DecodeBuf(packet, edx, dst, size);
        printf("[%p]DecodeBuf()=%p, %d\n", _ReturnAddress(), result, size);
        return result;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_DecodeBuf), Hook);
    }

    bool DecodeCoordF_Hook() {
      decltype(&DecodeCoordF) Hook = [](void* packet, void* edx, float* dst) -> float* {
        if (!logMutex[packet].try_lock()) {
          return _DecodeCoordF(packet, edx, dst);
        }

        float* result = _DecodeCoordF(packet, edx, dst);
        printf("[%p]DecodeCoordF()=<%f, %f, %f>\n", _ReturnAddress(), result[0], result[1], result[2]);
        logMutex.erase(packet);
        return result;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_DecodeCoordF), Hook);
    }

    bool DecodeCoordS_Hook() {
      decltype(&DecodeCoordS) Hook = [](void* packet, void* edx, __int16* dst) -> __int16* {
        if (!logMutex[packet].try_lock()) {
          return _DecodeCoordS(packet, edx, dst);
        }

        __int16* result = _DecodeCoordS(packet, edx, dst);
        printf("[%p]DecodeCoordS()=<%d, %d, %d>\n", _ReturnAddress(), result[0], result[1], result[2]);
        logMutex.erase(packet);
        return result;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_DecodeCoordS), Hook);
    }
  }

  bool Hook() {
    bool result = Init_Hook();
    result &= Decode1_Hook();
    result &= Decode2_Hook();
    result &= Decode4_Hook();
    result &= Decode8_Hook();
    result &= DecodeF_Hook();
    result &= DecodeWStrA_Hook();
    result &= DecodeStrA_Hook();
    result &= DecodeStrW_Hook();
    result &= DecodeBuf_Hook();
    result &= DecodeCoordF_Hook();
    result &= DecodeCoordS_Hook();

    return result;
  }
}
