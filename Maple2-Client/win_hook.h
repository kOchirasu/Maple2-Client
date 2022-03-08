#pragma once
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers

#include <Windows.h>

#define MUTLI_MUTEX		"Global\\7D9D84AE-A653-4C89-A004-26E262ECE0C4" /* Nexon's mutex key for checking MS2 Multi-Client */
#define CLIENT_CLASS    "MapleStory2" /* The class name of the main MapleStory2 window */

namespace win {
  BOOL Hook();
}
