#pragma once

namespace chat {
  struct ChatMessage {
    __int32 type;
    wchar_t* recipient;
    wchar_t* message;
    __int64 unknown;
  };

  bool Hook();
}
