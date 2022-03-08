#include "config.h"

namespace config {
  std::string WindowName;
  bool EnableMultiClient;

  bool Load(const std::string& path) {
    WindowName = "Maple2";
    EnableMultiClient = true;

    return true;
  }
}
