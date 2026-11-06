// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
#ifndef PHANTOM_MOSH_TERMINAL_STATE_H
#define PHANTOM_MOSH_TERMINAL_STATE_H
#include "record.h"
#include "src/statesync/completeterminal.h"
#include <algorithm>
#include <sys/wait.h>

namespace phantom {
// Terminal-profile draft-02 only. Metadata is part of the same reliable SSP
// state as the final screen, inside the existing authenticated encrypted DATA.
// Upstream Complete and the control/record protocols are unchanged.
class TerminalState : public Terminal::Complete
{
  unsigned char kind_ = 0; // 0 running, 1 normal exit, 2 signal
  unsigned char value_ = 0;

public:
  using Terminal::Complete::Complete;
  bool has_exit_status() const noexcept { return kind_ != 0; }
  int exit_code() const
  {
    if ( !kind_ )
      throw Error( "remote shell exit status unavailable" );
    return kind_ == 1 ? value_ : std::min( 255, 128 + static_cast<int>( value_ ) );
  }
  void set_wait_status( int status )
  {
    unsigned char kind, value;
    if ( WIFEXITED( status ) ) {
      kind = 1;
      value = static_cast<unsigned char>( WEXITSTATUS( status ) );
    } else if ( WIFSIGNALED( status ) ) {
      kind = 2;
      value = static_cast<unsigned char>( WTERMSIG( status ) );
    } else {
      throw Error( "nonfinal shell status" );
    }
    if ( kind_ && ( kind_ != kind || value_ != value ) )
      throw Error( "remote shell status changed" );
    kind_ = kind;
    value_ = value;
  }
  void subtract( const TerminalState* ) const {}
  std::string diff_from( const TerminalState& previous ) const
  {
    auto body = Terminal::Complete::diff_from( previous );
    if ( body.empty() && kind_ == previous.kind_ && value_ == previous.value_ )
      return {};
    std::string result( "PTS\002", 4 );
    result.push_back( static_cast<char>( kind_ ) );
    result.push_back( static_cast<char>( value_ ) );
    return result + body;
  }
  std::string init_diff() const
  {
    return diff_from( TerminalState( get_fb().ds.get_width(), get_fb().ds.get_height() ) );
  }
  void apply_string( const std::string& diff )
  {
    if ( diff.empty() )
      return;
    if ( diff.size() < 6 || diff.compare( 0, 4, "PTS\002", 4 ) != 0 )
      throw Error( "invalid terminal state envelope" );
    const auto kind = static_cast<unsigned char>( diff[4] );
    const auto value = static_cast<unsigned char>( diff[5] );
    if ( kind > 2 || ( kind == 0 && value != 0 ) || ( kind == 2 && ( value == 0 || value >= NSIG ) )
         || ( kind_ && ( kind != kind_ || value != value_ ) ) )
      throw Error( "invalid terminal exit status" );
    Terminal::Complete::apply_string( diff.substr( 6 ) );
    kind_ = kind;
    value_ = value;
  }
  bool operator==( const TerminalState& other ) const
  {
    return kind_ == other.kind_ && value_ == other.value_ && Terminal::Complete::operator==( other );
  }
  bool compare( const TerminalState& other ) const
  {
    return kind_ != other.kind_ || value_ != other.value_ || Terminal::Complete::compare( other );
  }
};
} // namespace phantom
#endif
