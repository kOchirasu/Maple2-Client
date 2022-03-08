#pragma once
#include <string>

namespace config {
  extern std::string WindowName;
  extern bool EnableMultiClient;

  bool Load(const std::string& path);
}
