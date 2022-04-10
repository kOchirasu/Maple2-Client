#include "atlstr.h"
#include <sstream>
#include <map>
#include <mutex>
#include <format>
#include "../hook.h"
#include "inpacket_hook.h"
#include "packet_tracker.h"

#define CInPacket_decrypt 0x005E2500
#define CInPacket_delete  0x00A7D8D0
#define CInPacket_init    0x005E2730
#define CInPacket_vtable  0x01809CBC

namespace packet {
  namespace {
#pragma region Definitions
    // __thiscall becomes __fastcall with edx as 2nd param.
    __int16(__fastcall Init)(int* packet_base, void* edx);
    void* (__fastcall Decrypt)(int* packet_base, void* edx, void* a2, void* a3);
    void* (__fastcall Delete)(int* packet_base, void* edx, __int8 free);
    bool(__fastcall DecodeB)(CInPacket* packet, void* edx);
    __int8(__fastcall Decode1)(CInPacket* packet, void* edx);
    __int16(__fastcall Decode2)(CInPacket* packet, void* edx);
    __int32(__fastcall Decode4)(CInPacket* packet, void* edx);
    __int64(__fastcall Decode8)(CInPacket* packet, void* edx);
    float(__fastcall DecodeF)(CInPacket* packet, void* edx);
    CStringA* (__fastcall DecodeWStrA)(CInPacket* packet, void* edx, CStringA* dst);
    CStringA* (__fastcall DecodeStrA)(CInPacket* packet, void* edx, CStringA* dst);
    CStringW* (__fastcall DecodeStrW)(CInPacket* packet, void* edx, CStringW* dst);
    void* (__fastcall DecodeBuf)(CInPacket* packet, void* edx, void* dst, size_t size);
    float* (__fastcall DecodeCoordF)(CInPacket* packet, void* edx, float* dst);
    __int16* (__fastcall DecodeCoordS)(CInPacket* packet, void* edx, __int16* dst);
    // float (__fastcall Decode2ft10)(CInPacket* packet, void* edx);
    // float (__fastcall Decode2ft100)(CInPacket* packet, void* edx);
    // float (__fastcall Decode2ftx)(CInPacket* packet, void* edx, float mul);
    // float (__fastcall Decode2fd10)(CInPacket* packet, void* edx);
    // float (__fastcall Decode2fdx)(CInPacket* packet, void* edx, float div);
#pragma endregion

    // These mutexes are used to prevent the same value from being logged in multiple functions.
    static std::map<void*, std::mutex> logMutex;
    static PacketTracker tracker;

    bool Init_Hook() {
      static auto _Init = reinterpret_cast<decltype(&Init)>(CInPacket_init);
      decltype(&Init) Hook = [](int* packet_base, void* edx) -> __int16 {
        void* key = static_cast<void*>(packet_base + 1);
        if (!logMutex[key].try_lock()) {
          return _Init(packet_base, edx);
        }

        __int16 opcode = _Init(packet_base, edx);
        auto packet = reinterpret_cast<CInPacket*>(key);
        tracker.SetOp(packet, opcode, { packet->offset, EntryType::Short, _ReturnAddress() });
        //printf("[%p]InitIn(%p)=%04X\n", _ReturnAddress(), key, opcode);
        logMutex.erase(key);
        return opcode;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_Init), Hook);
    }

    bool Decrypt_Hook() {
      static auto _Decrypt = reinterpret_cast<decltype(&Decrypt)>(CInPacket_decrypt);
      decltype(&Decrypt) Hook = [](int* packet_base, void* edx, void* a2, void* a3) -> void* {
        tracker.Create(reinterpret_cast<void*>(packet_base + 1));
        //printf("[%p]Decrypt(%p)\n", _ReturnAddress(), packet_base+1);
        return _Decrypt(packet_base, edx, a2, a3);
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_Decrypt), Hook);
    }

    bool Delete_Hook() {
      static auto _Delete = reinterpret_cast<decltype(&Delete)>(CInPacket_delete);
      decltype(&Delete) Hook = [](int* packet_base, void* edx, __int8 free) -> void* {
        std::optional<PacketChain> chain = tracker.Finalize(reinterpret_cast<void*>(packet_base + 4));
        if (chain.has_value()) {
          std::stringstream ss;
          ss << std::format("[{:04X}]  IN ", chain->op);
          for (const PacketEntry& entry : chain->entries) {
            ss << entry;
          }
          std::cout << ss.str() << std::endl;
        }
        //printf("[%p]Delete(%p)=%d\n", _ReturnAddress(), packet_base+4, free);
        return _Delete(packet_base, edx, free);
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_Delete), Hook);
    }

    bool DecodeB_Hook() {
      static auto _DecodeB = hook::GetVtableFunc<decltype(&DecodeB)>(CInPacket_vtable, 0);
      decltype(&DecodeB) Hook = [](CInPacket* packet, void* edx) -> bool {
        if (!logMutex[packet].try_lock()) {
          return _DecodeB(packet, edx);
        }

        tracker.Append(packet, { packet->offset, EntryType::Bool, _ReturnAddress() });
        __int8 result = _DecodeB(packet, edx);
        //printf("[%p]DecodeB()=%d\n", _ReturnAddress(), result);
        logMutex.erase(packet);
        return result;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_DecodeB), Hook);
    }

    bool Decode1_Hook() {
      static auto _Decode1 = hook::GetVtableFunc<decltype(&Decode1)>(CInPacket_vtable, 1);
      decltype(&Decode1) Hook = [](CInPacket* packet, void* edx) -> __int8 {
        if (!logMutex[packet].try_lock()) {
          return _Decode1(packet, edx);
        }

        tracker.Append(packet, { packet->offset, EntryType::Byte, _ReturnAddress() });
        __int8 result = _Decode1(packet, edx);
        //printf("[%p]Decode1()=%d\n", _ReturnAddress(), result);
        logMutex.erase(packet);
        return result;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_Decode1), Hook);
    }

    bool Decode2_Hook() {
      static auto _Decode2 = hook::GetVtableFunc<decltype(&Decode2)>(CInPacket_vtable, 2);
      decltype(&Decode2) Hook = [](CInPacket* packet, void* edx) -> __int16 {
        if (!logMutex[packet].try_lock()) {
          return _Decode2(packet, edx);
        }

        tracker.Append(packet, { packet->offset, EntryType::Short, _ReturnAddress()});
        __int16 result = _Decode2(packet, edx);
        //printf("[%p]Decode2()=%d\n", _ReturnAddress(), result);
        logMutex.erase(packet);
        return result;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_Decode2), Hook);
    }

    bool Decode4_Hook() {
      static auto _Decode4 = hook::GetVtableFunc<decltype(&Decode4)>(CInPacket_vtable, 3);
      decltype(&Decode4) Hook = [](CInPacket* packet, void* edx) -> __int32 {
        tracker.Append(packet, { packet->offset, EntryType::Int, _ReturnAddress() });
        __int32 result = _Decode4(packet, edx);
        //printf("[%p]Decode4()=%d\n", _ReturnAddress(), result);
        return result;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_Decode4), Hook);
    }

    bool Decode8_Hook() {
      static auto _Decode8 = hook::GetVtableFunc<decltype(&Decode8)>(CInPacket_vtable, 4);
      decltype(&Decode8) Hook = [](CInPacket* packet, void* edx) -> __int64 {
        tracker.Append(packet, { packet->offset, EntryType::Long, _ReturnAddress() });
        __int64 result = _Decode8(packet, edx);
        //printf("[%p]Decode8()=%lld\n", _ReturnAddress(), result);
        return result;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_Decode8), Hook);
    }

    bool DecodeF_Hook() {
      static auto _DecodeF = hook::GetVtableFunc<decltype(&DecodeF)>(CInPacket_vtable, 5);
      decltype(&DecodeF) Hook = [](CInPacket* packet, void* edx) -> float {
        if (!logMutex[packet].try_lock()) {
          return _DecodeF(packet, edx);
        }

        tracker.Append(packet, { packet->offset, EntryType::Float, _ReturnAddress() });
        float result = _DecodeF(packet, edx);
        //printf("[%p]DecodeF()=%f\n", _ReturnAddress(), result);
        logMutex.erase(packet);
        return result;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_DecodeF), Hook);
    }

    bool DecodeWStrA_Hook() {
      static auto _DecodeWStrA = hook::GetVtableFunc<decltype(&DecodeWStrA)>(CInPacket_vtable, 6);
      decltype(&DecodeWStrA) Hook = [](CInPacket* packet, void* edx, CStringA* dst) -> CStringA* {
        if (!logMutex[packet].try_lock()) {
          return _DecodeWStrA(packet, edx, dst);
        }

        tracker.Append(packet, { packet->offset, EntryType::WString, _ReturnAddress() });
        CStringA* result = _DecodeWStrA(packet, edx, dst);
        //printf("[%p]DecodeWStrA()=\"%s\"\n", _ReturnAddress(), result->GetString());
        logMutex.erase(packet);
        return result;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_DecodeWStrA), Hook);
    }

    bool DecodeStrA_Hook() {
      static auto _DecodeStrA = hook::GetVtableFunc<decltype(&DecodeStrA)>(CInPacket_vtable, 7);
      decltype(&DecodeStrA) Hook = [](CInPacket* packet, void* edx, CStringA* dst) -> CStringA* {
        if (!logMutex[packet].try_lock()) {
          return _DecodeStrA(packet, edx, dst);
        }

        tracker.Append(packet, { packet->offset, EntryType::String, _ReturnAddress() });
        CStringA* result = _DecodeStrA(packet, edx, dst);
        //printf("[%p]DecodeStrA()=\"%s\"\n", _ReturnAddress(), result->GetString());
        logMutex.erase(packet);
        return result;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_DecodeStrA), Hook);
    }

    bool DecodeStrW_Hook() {
      static auto _DecodeStrW = hook::GetVtableFunc<decltype(&DecodeStrW)>(CInPacket_vtable, 8);
      decltype(&DecodeStrW) Hook = [](CInPacket* packet, void* edx, CStringW* dst) -> CStringW* {
        if (!logMutex[packet].try_lock()) {
          return _DecodeStrW(packet, edx, dst);
        }

        tracker.Append(packet, { packet->offset, EntryType::WString, _ReturnAddress() });
        CStringW* result = _DecodeStrW(packet, edx, dst);
        //printf("[%p]DecodeStrW()=\"%ls\"\n", _ReturnAddress(), result->GetString());
        logMutex.erase(packet);
        return result;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_DecodeStrW), Hook);
    }

    bool DecodeBuf_Hook() {
      static auto _DecodeBuf = hook::GetVtableFunc<decltype(&DecodeBuf)>(CInPacket_vtable, 9);
      decltype(&DecodeBuf) Hook = [](CInPacket* packet, void* edx, void* dst, size_t size) -> void* {
        tracker.Append(packet, { packet->offset, EntryType::Buffer, _ReturnAddress() });
        void* result = _DecodeBuf(packet, edx, dst, size);

        //printf("[%p]DecodeBuf()=%p, %d\n", _ReturnAddress(), result, size);
        return result;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_DecodeBuf), Hook);
    }

    bool DecodeCoordF_Hook() {
      static auto _DecodeCoordF = hook::GetVtableFunc<decltype(&DecodeCoordF)>(CInPacket_vtable, 10);
      decltype(&DecodeCoordF) Hook = [](CInPacket* packet, void* edx, float* dst) -> float* {
        if (!logMutex[packet].try_lock()) {
          return _DecodeCoordF(packet, edx, dst);
        }

        tracker.Append(packet, { packet->offset, EntryType::CoordF, _ReturnAddress() });
        float* result = _DecodeCoordF(packet, edx, dst);
        //printf("[%p]DecodeCoordF()=<%f, %f, %f>\n", _ReturnAddress(), result[0], result[1], result[2]);
        logMutex.erase(packet);
        return result;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_DecodeCoordF), Hook);
    }

    bool DecodeCoordS_Hook() {
      static auto _DecodeCoordS = hook::GetVtableFunc<decltype(&DecodeCoordS)>(CInPacket_vtable, 11);
      decltype(&DecodeCoordS) Hook = [](CInPacket* packet, void* edx, __int16* dst) -> __int16* {
        if (!logMutex[packet].try_lock()) {
          return _DecodeCoordS(packet, edx, dst);
        }

        tracker.Append(packet, { packet->offset, EntryType::CoordS, _ReturnAddress() });
        __int16* result = _DecodeCoordS(packet, edx, dst);
        //printf("[%p]DecodeCoordS()=<%d, %d, %d>\n", _ReturnAddress(), result[0], result[1], result[2]);
        logMutex.erase(packet);
        return result;
      };

      return hook::SetHook(TRUE, reinterpret_cast<void**>(&_DecodeCoordS), Hook);
    }
  }

  bool HookIn() {
    bool result = Init_Hook();
    result &= Decrypt_Hook();
    result &= Delete_Hook();
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
