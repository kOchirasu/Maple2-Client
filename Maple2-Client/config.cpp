#include "config.h"

namespace config {
  std::string WindowName;
  std::string Locale;
  std::string HostName;
  unsigned short Port;

  bool BypassBanWord;
  bool EnableMultiClient;
  bool DisableNXL;
  bool BypassNGS;

  bool Load(const std::string& path) {
    WindowName = "Maple2";
    Locale = "EN";
    HostName = "localhost";
    Port = 20001;

    BypassBanWord = true;
    EnableMultiClient = true;
    DisableNXL = true;
    BypassNGS = true;

    return true;
  }
}
