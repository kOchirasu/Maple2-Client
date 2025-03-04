#include "config.h"
#include "inipp.h"
#include <iostream>
#include <fstream>

namespace config {
  namespace {
    template<class T>
    T as(const std::string& str);

    template<>
    std::string as(const std::string& str) {
      return str;
    }

    template<class Integer>
    Integer as(const std::string& str) {
      return std::stoi(str);
    }

    template<>
    bool as(const std::string& str) {
      const std::string sTrue = "true";
      if (str.size() != sTrue.size()) {
        return false;
      }
      for (unsigned int i = 0; i < sTrue.size(); i++) {
        if (std::tolower(str[i]) != sTrue[i]) {
          return false;
        }
      }

      return true;
    }

    template<class T>
    T AtOrDefault(const std::map<std::string, std::string>& map, const std::string& key, const T& value = 0) {
      if (map.find(key) == map.end()) {
        return value;
      }

      return as<T>(map.at(key));
    }
  }

  // Required so these are not configurable.
  bool DisableNXL = true;
  bool BypassNGS = true;

  // Custom configuration
  std::string WindowName;
  std::string Locale;
  std::string HostName;
  unsigned short Port;

  bool LogExceptions;
  bool BypassBanWord;
  bool EnableMultiClient;
  bool EnableVisualizer;
  std::string UgdUrl;

  bool HookOutPacket;
  bool HookInPacket;

  bool EnableCefHook;

  DWORD* ServiceManager;
  DWORD* MS2VisualTracker;

  bool Load(const std::string& path) {
    inipp::Ini<char> ini;
    std::ifstream file;
    file.open(path);

    if (!file.is_open()) {
      std::cerr << "Failed to open config file: " << path << std::endl;
      //return false;
    } else {
      ini.parse(file);

      ini.default_section(ini.sections["default"]);
      ini.interpolate();

      // Print config to cout
      std::cout << "Using config file: " << path << std::endl;
      ini.generate(std::cout);
    }

    auto &cfg = ini.sections["default"];
    WindowName = AtOrDefault<std::string>(cfg, "name", "MapleStory2");
    Locale = AtOrDefault<std::string>(cfg, "locale", "EN");
    HostName = AtOrDefault<std::string>(cfg, "host", "localhost");
    Port = AtOrDefault<unsigned short>(cfg, "port", 20001);

    LogExceptions = AtOrDefault<bool>(cfg, "log_exceptions");
    BypassBanWord = AtOrDefault<bool>(cfg, "banword");
    EnableMultiClient = AtOrDefault<bool>(cfg, "multiclient");
    EnableVisualizer = AtOrDefault<bool>(cfg, "visualizer");
    UgdUrl = AtOrDefault<std::string>(cfg, "ugd_url", "");

    HookOutPacket = AtOrDefault<bool>(cfg, "hook_outpacket", false);
    HookInPacket = AtOrDefault<bool>(cfg, "hook_inpacket", false);

    EnableCefHook = AtOrDefault<bool>(cfg, "hook_cef", true);

    return true;
  }
}
