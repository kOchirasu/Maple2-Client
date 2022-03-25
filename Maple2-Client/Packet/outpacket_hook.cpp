#include "atlstr.h"
#include <iostream>
#include <map>
#include <mutex>
#include "../hook.h"
#include "outpacket_hook.h";

#define COutPacket_init     0x005E2960
#define COutPacket_vtable   0x017C9844

namespace outpacket {
  namespace {
#pragma region Definitions
    // __thiscall becomes __fastcall with edx as 2nd param.
    void* (__fastcall Init)(void* packet, void* edx, __int32 opcode, __int32 unk);
    static auto _Init = reinterpret_cast<decltype(&Init)>(COutPacket_init);

    void* (__fastcall EncodeB)(void* packet, void* edx, bool value);
    static auto _EncodeB = hook::GetVtableFunc<decltype(&EncodeB)>(COutPacket_vtable, 0);

    void* (__fastcall Encode1)(void* packet, void* edx, __int8 value);
    static auto _Encode1 = hook::GetVtableFunc<decltype(&Encode1)>(COutPacket_vtable, 1);

    void* (__fastcall Encode2)(void* packet, void* edx, __int16 value);
    static auto _Encode2 = hook::GetVtableFunc<decltype(&Encode2)>(COutPacket_vtable, 2);

    void* (__fastcall Encode4)(void* packet, void* edx, __int32 value);
    static auto _Encode4 = hook::GetVtableFunc<decltype(&Encode4)>(COutPacket_vtable, 3);

    void* (__fastcall Encode8)(void* packet, void* edx, __int32 loValue, __int32 hiValue);
    static auto _Encode8 = hook::GetVtableFunc<decltype(&Encode8)>(COutPacket_vtable, 4);

    void* (__fastcall EncodeF)(void* packet, void* edx, float value);
    static auto _EncodeF = hook::GetVtableFunc<decltype(&EncodeF)>(COutPacket_vtable, 5);

    void(__fastcall EncodeAStrW)(void* packet, void* edx, CStringA* value);
    static auto _EncodeAStrW = hook::GetVtableFunc<decltype(&EncodeAStrW)>(COutPacket_vtable, 6);

    void(__fastcall EncodeStrA)(void* packet, void* edx, CStringA* value);
    static auto _EncodeStrA = hook::GetVtableFunc<decltype(&EncodeStrA)>(COutPacket_vtable, 7);

    void(__fastcall EncodeStrW)(void* packet, void* edx, CStringW* value);
    static auto _EncodeStrW = hook::GetVtableFunc<decltype(&EncodeStrW)>(COutPacket_vtable, 8);

    void* (__fastcall EncodeBuf)(void* packet, void* edx, void* value, size_t size);
    static auto _EncodeBuf = hook::GetVtableFunc<decltype(&EncodeBuf)>(COutPacket_vtable, 9);

    void* (__fastcall EncodeCoordF)(void* packet, void* edx, float* values);
    static auto _EncodeCoordF = hook::GetVtableFunc<decltype(&EncodeCoordF)>(COutPacket_vtable, 10);

    void* (__fastcall EncodeCoordS)(void* packet, void* edx, float* values);
    static auto _EncodeCoordS = hook::GetVtableFunc<decltype(&EncodeCoordS)>(COutPacket_vtable, 11);

    // void* (__fastcall Encode2fd10)(void* packet, void* edx, float value);
    // void* (__fastcall Encode2fd100)(void* packet, void* edx, float value);
    // void* (__fastcall Encode2fdx)(void* packet, void* edx, float value, float div);
    // void* (__fastcall Encode2ft10)(void* packet, void* edx, float value);
    // void* (__fastcall Encode2ftx)(void* packet, void* edx, float value, float mul);
#pragma endregion

    // These mutexes are used to prevent the same value from being logged in multiple functions.
    static std::map<void*, std::mutex> logMutex;

    bool Init_Hook() {
      decltype(&Init) Hook = [](void* packet, void* edx, __int32 opcode, __int32 unk) -> void* {
        if (!logMutex[packet].try_lock()) {
          return _Init(packet, edx, opcode, unk);
        }

        // 0x7FFFFFFF is used to avoid writing opcode. Used for copying packets before send?
        if (opcode != 0x7FFFFFFF) {
          printf("[%p]InitOut(%04X)\n", _ReturnAddress(), opcode);
        }

        void* result = _Init(packet, edx, opcode, unk);
        logMutex.erase(packet);
        return result;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_Init), Hook);
    }

    bool EncodeB_Hook() {
      decltype(&EncodeB) Hook = [](void* packet, void* edx, bool value) -> void* {
        if (!logMutex[packet].try_lock()) {
          return _EncodeB(packet, edx, value);
        }

        printf("[%p]EncodeB(%d)\n", _ReturnAddress(), value);
        void* result = _EncodeB(packet, edx, value);
        logMutex.erase(packet);
        return result;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_EncodeB), Hook);
    }

    bool Encode1_Hook() {
      decltype(&Encode1) Hook = [](void* packet, void* edx, __int8 value) -> void* {
        if (!logMutex[packet].try_lock()) {
          return _Encode1(packet, edx, value);
        }

        printf("[%p]Encode1(%d)\n", _ReturnAddress(), value);
        void* result = _Encode1(packet, edx, value);
        logMutex.erase(packet);
        return result;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_Encode1), Hook);
    }

    bool Encode2_Hook() {
      decltype(&Encode2) Hook = [](void* packet, void* edx, __int16 value) -> void* {
        if (!logMutex[packet].try_lock()) {
          return _Encode2(packet, edx, value);
        }

        printf("[%p]Encode2(%d)\n", _ReturnAddress(), value);
        void* result = _Encode2(packet, edx, value);
        logMutex.erase(packet);
        return result;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_Encode2), Hook);
    }

    bool Encode4_Hook() {
      decltype(&Encode4) Hook = [](void* packet, void* edx, __int32 value) -> void* {
        printf("[%p]Encode4(%d)\n", _ReturnAddress(), value);
        return _Encode4(packet, edx, value);
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_Encode4), Hook);
    }

    bool Encode8_Hook() {
      decltype(&Encode8) Hook = [](void* packet, void* edx, __int32 loValue, __int32 hiValue) -> void* {
        printf("[%p]Encode8(%lld)\n", _ReturnAddress(), (__int64)hiValue << 32 | loValue);
        return _Encode8(packet, edx, loValue, hiValue);
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_Encode8), Hook);
    }

    bool EncodeF_Hook() {
      decltype(&EncodeF) Hook = [](void* packet, void* edx, float value) -> void* {
        if (!logMutex[packet].try_lock()) {
          return _EncodeF(packet, edx, value);
        }

        printf("[%p]EncodeF(%f)\n", _ReturnAddress(), value);
        void* result = _EncodeF(packet, edx, value);
        logMutex.erase(packet);
        return result;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_EncodeF), Hook);
    }

    bool EncodeAStrW_Hook() {
      decltype(&EncodeStrA) Hook = [](void* packet, void* edx, CStringA* value) -> void {
        if (!logMutex[packet].try_lock()) {
          _EncodeAStrW(packet, edx, value);
          return;
        }

        printf("[%p]EncodeAStrW(\"%s\")\n", _ReturnAddress(), value->GetString());
        _EncodeAStrW(packet, edx, value);
        logMutex.erase(packet);
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_EncodeAStrW), Hook);
    }

    bool EncodeStrA_Hook() {
      decltype(&EncodeStrA) Hook = [](void* packet, void* edx, CStringA* value) -> void {
        if (!logMutex[packet].try_lock()) {
          _EncodeStrA(packet, edx, value);
          return;
        }

        printf("[%p]EncodeStrA(\"%s\")\n", _ReturnAddress(), value->GetString());
        _EncodeStrA(packet, edx, value);
        logMutex.erase(packet);
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_EncodeStrA), Hook);
    }

    bool EncodeStrW_Hook() {
      decltype(&EncodeStrW) Hook = [](void* packet, void* edx, CStringW* value) -> void {
        if (!logMutex[packet].try_lock()) {
          _EncodeStrW(packet, edx, value);
          return;
        }

        printf("[%p]EncodeStrW(\"%ls\")\n", _ReturnAddress(), value->GetString());
        _EncodeStrW(packet, edx, value);
        logMutex.erase(packet);
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_EncodeStrW), Hook);
    }

    bool EncodeBuf_Hook() {
      decltype(&EncodeBuf) Hook = [](void* packet, void* edx, void* value, size_t size) -> void* {
        printf("[%p]EncodeBuf(%p, %d)\n", _ReturnAddress(), value, size);
        return _EncodeBuf(packet, edx, value, size);
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_EncodeBuf), Hook);
    }

    bool EncodeCoordF_Hook() {
      decltype(&EncodeCoordF) Hook = [](void* packet, void* edx, float* values) -> void* {
        if (!logMutex[packet].try_lock()) {
          return _EncodeCoordF(packet, edx, values);
        }

        printf("[%p]EncodeCoordF(%f, %f, %f)\n", _ReturnAddress(), values[0], values[1], values[2]);
        void* result = _EncodeCoordF(packet, edx, values);
        logMutex.erase(packet);
        return result;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_EncodeCoordF), Hook);
    }

    bool EncodeCoordS_Hook() {
      decltype(&EncodeCoordS) Hook = [](void* packet, void* edx, float* values) -> void* {
        if (!logMutex[packet].try_lock()) {
          return _EncodeCoordS(packet, edx, values);
        }

        __int16 x = static_cast<__int16>(values[0] + (values[0] >= 0 ? 0.001f : -0.001f));
        __int16 y = static_cast<__int16>(values[1] + (values[1] >= 0 ? 0.001f : -0.001f));
        __int16 z = static_cast<__int16>(values[2] + 0.001f);
        printf("[%p]EncodeCoordS(%d, %d, %d)\n", _ReturnAddress(), x, y, z);
        void* result = _EncodeCoordS(packet, edx, values);
        logMutex.erase(packet);
        return result;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_EncodeCoordS), Hook);
    }
  }

  bool Hook() {
    bool result = Init_Hook();
    result &= EncodeB_Hook();
    result &= Encode1_Hook();
    result &= Encode2_Hook();
    result &= Encode4_Hook();
    result &= Encode8_Hook();
    result &= EncodeF_Hook();
    result &= EncodeAStrW_Hook();
    result &= EncodeStrA_Hook();
    result &= EncodeStrW_Hook();
    result &= EncodeBuf_Hook();
    result &= EncodeCoordF_Hook();
    result &= EncodeCoordS_Hook();

    return result;
  }
}
