#pragma once
#include <string>

#define LOG_BUFFER 1024

namespace config {
  extern std::string WindowName;
  extern std::string HostName;
  extern unsigned short Port;

  extern bool EnableChatSpam;
  extern bool DisableSwearFilter;
  extern bool EnableMultiClient;
  extern bool DisableNXL;
  extern bool BypassNGS;

  bool Load(const std::string& path);
}
