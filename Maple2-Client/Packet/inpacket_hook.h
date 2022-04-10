#pragma once

namespace packet {
  struct CInPacket {
    DWORD_PTR vtbl;
    int unk1;
    int unk2;
    int unk3;
    int unk4;
    int unk5;
    int unk6;
    int length; // length
    int unk8;
    int unk9;
    int data_length; // length - 6
    int offset; // offset
  };

  bool HookIn();
}
