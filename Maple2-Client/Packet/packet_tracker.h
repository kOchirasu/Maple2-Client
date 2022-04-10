#pragma once

#include <iostream>
#include <list>
#include <map>
#include <optional>

namespace packet {
  const int HEADER_SIZE = 6;

  enum class EntryType {
    Unknown, Bool, Byte, Short, Int, Long, Float, Buffer, String, WString, CoordF, CoordS
  };

  struct PacketEntry {
    int offset = 0;
    EntryType type = EntryType::Unknown;
    void* return_addr = 0;

    friend std::ostream& operator<<(std::ostream& os, const PacketEntry& pe) {
      os << '[' << pe.offset << ':' << pe.return_addr << '/';
      switch (pe.type) {
        case EntryType::Bool:
          os << 'B';
          break;
        case EntryType::Byte:
          os << 1;
          break;
        case EntryType::Short:
          os << 2;
          break;
        case EntryType::Int:
          os << 4;
          break;
        case EntryType::Long:
          os << 8;
          break;
        case EntryType::Float:
          os << 'F';
          break;
        case EntryType::Buffer:
          os << "buf";
          break;
        case EntryType::String:
          os << "str";
          break;
        case EntryType::WString:
          os << "wstr";
          break;
        case EntryType::CoordF:
          os << "3f";
          break;
        case EntryType::CoordS:
          os << "3s";
          break;
        default:
          os << "unk";
      }
      os << "] ";
      return os;
    }
  };

  struct PacketChain {
    std::list<PacketEntry> entries;
    int offset = -1;
    short op = -1;
  };

  class PacketTracker {
  public:
    bool Create(void* base) {
      PacketChain chain;
      auto it = dict.try_emplace(base, std::move(chain));
      return it.second;
    }

    bool SetOp(void* base, short op, PacketEntry entry) {
      auto it = dict.find(base);
      if (it == dict.end()) {
        return false;
      }

      // SetOp is called when DecodeHeader is invoked. This resets the packet offset.
      PacketChain& chain = it->second;
      chain.op = op;
      chain.offset = HEADER_SIZE;
      entry.offset = HEADER_SIZE;
      chain.entries.clear();
      chain.entries.push_back(std::move(entry));
      return true;
    }

    bool Append(void* base, PacketEntry entry) {
      auto it = dict.find(base);
      if (it == dict.end()) {
        return false;
      }

      PacketChain& chain = it->second;
      // duplicate result
      if (entry.offset <= chain.offset) {
        return false;
      }

      chain.offset = entry.offset;
      chain.entries.push_back(std::move(entry));
      return true;
    }

    std::optional<PacketChain> Finalize(void* base) {
      auto it = dict.find(base);
      if (it == dict.end()) {
        return std::nullopt;
      }

      PacketChain result = it->second;
      dict.erase(it);
      return result;
    }

  private:
    std::map<void*, PacketChain> dict;
  };
}
