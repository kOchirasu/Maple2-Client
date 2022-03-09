#pragma once
#include <string>

namespace config {
  extern std::string WindowName;
  extern std::string Locale;
  extern std::string HostName;
  extern unsigned short Port;

  extern bool BypassBanWord;
  extern bool EnableMultiClient;
  extern bool DisableNXL;
  extern bool BypassNGS;

  bool Load(const std::string& path);
}
