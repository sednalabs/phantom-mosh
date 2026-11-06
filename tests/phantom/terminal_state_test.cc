// SPDX-License-Identifier: GPL-3.0-or-later
#include "terminal_options.h"
#include "terminal_state.h"
#include <clocale>
#include <iomanip>
#include <iostream>
using namespace phantom;
void require( bool value, const char* message )
{
  if ( !value )
    throw Error( message );
}
int main( int argc, char** argv )
{
  try {
    require( std::setlocale( LC_ALL, "C.UTF-8" ), "locale" );
    if ( argc == 2 && std::string( argv[1] ) == "--vectors" ) {
      for ( int status : { 0, 7 << 8, 255 << 8, SIGKILL } ) {
        TerminalState state( 80, 24 );
        state.set_wait_status( status );
        for ( unsigned char byte : state.init_diff() )
          std::cout << std::hex << std::setfill( '0' ) << std::setw( 2 ) << static_cast<unsigned>( byte );
        std::cout << '\n';
      }
      return 0;
    }
    for ( int code : { 0, 1, 7, 255 } ) {
      TerminalState blank( 80, 24 ), final( blank ), received( blank );
      final.act( std::string( "final output" ) );
      final.set_wait_status( code << 8 );
      auto diff = final.diff_from( blank );
      require( !diff.empty(), "status must create an SSP update" );
      received.apply_string( diff );
      require( !received.compare( final ) && received.exit_code() == code, "screen and status round trip" );
      require( received.has_exit_status(), "zero exit differs from missing status" );
      TerminalState status_only( blank );
      status_only.set_wait_status( code << 8 );
      received.apply_string( status_only.init_diff() );
      require( !received.compare( final ) && received.exit_code() == code, "idempotent status metadata" );
      require( final.diff_from( final ).empty(), "unchanged state emits no diff" );
      TerminalState recovered( blank );
      recovered.apply_string( final.init_diff() );
      require( !recovered.compare( final ) && recovered.exit_code() == code,
               "status survives full state recovery" );
    }
    TerminalState killed( 80, 24 ), received( 80, 24 );
    killed.set_wait_status( SIGKILL );
    received.apply_string( killed.init_diff() );
    require( received.exit_code() == 137, "signal status" );
    const auto original = received;
    for ( const auto& bad : { std::string( "short" ),
                              std::string( "PTS\001\001\000", 6 ),
                              std::string( "PTS\002\003\000", 6 ),
                              std::string( "PTS\002\000\001", 6 ),
                              std::string( "PTS\002\002\000", 6 ),
                              std::string( "PTS\002\002\377", 6 ),
                              std::string( "PTS\002\000\000", 6 ),
                              std::string( "PTS\002\001\007", 6 ) } ) {
      bool rejected = false;
      try {
        received.apply_string( bad );
      } catch ( const Error& ) {
        rejected = true;
      }
      require( rejected && received == original, "malformed/changed status rejected atomically" );
    }
    TerminalState running( 80, 24 );
    require( running.compare( killed ) && !( running == killed ), "status participates in full state comparison" );
    bool rejected = false;
    try {
      (void)running.exit_code();
    } catch ( const Error& ) {
      rejected = true;
    }
    require( rejected, "missing exit is never success" );
    TerminalOptions options;
    options.validate();
    for ( const auto& shell : { "sh", "", "/bin/sh\n" } ) {
      options.shell = shell;
      rejected = false;
      try {
        options.validate();
      } catch ( const Error& ) {
        rejected = true;
      }
      require( rejected, "invalid shell rejected" );
    }
    options.shell = "/tmp/shell with 'quotes'; $literal";
    options.validate();
    options.term = "vt100";
    options.validate();
    options.term = "xterm;anything";
    rejected = false;
    try {
      options.validate();
    } catch ( const Error& ) {
      rejected = true;
    }
    require( rejected, "invalid TERM rejected" );
    std::cout << "terminal state and option tests passed\n";
    return 0;
  } catch ( const std::exception& error ) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
