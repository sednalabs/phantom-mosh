// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef PHANTOM_MOSH_TERMINAL_OPTIONS_H
#define PHANTOM_MOSH_TERMINAL_OPTIONS_H
#include "record.h"
#include <algorithm>
#include <string>
namespace phantom {
struct TerminalOptions
{
  std::string shell = "/bin/sh";
  std::string term = "xterm-256color";
  void validate() const
  {
    if ( shell.empty() || shell[0] != '/' || shell.size() > 4096
         || !std::all_of( shell.begin(), shell.end(), []( unsigned char c ) { return c >= 32 && c < 127; } ) )
      throw Error( "invalid absolute terminal shell path" );
    if ( term.empty() || term.size() > 64
         || term.find_first_not_of( "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+-" )
              != std::string::npos )
      throw Error( "invalid terminal TERM" );
  }
};
} // namespace phantom
#endif
