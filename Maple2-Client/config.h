#pragma once
#include <Windows.h>
#include <string>

namespace config {
  extern bool DisableNXL;
  extern bool BypassNGS;

  extern std::string WindowName;
  extern std::string Locale;
  extern std::string HostName;
  extern unsigned short Port;

  extern bool LogExceptions;
  extern bool BypassBanWord;
  extern bool EnableMultiClient;
  extern bool EnableVisualizer;

  // Packet Hooks
  extern bool HookOutPacket;
  extern bool HookInPacket;

  // Global pointer to keep track of GameBryo ServiceManager
  extern DWORD* ServiceManager;
  extern DWORD* MS2VisualTracker;

  bool Load(const std::string& path);
}
