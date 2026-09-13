// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
#include "ssp_timing.h"
#include "ssp_test.h"
#include <cmath>
#include <iostream>

using namespace phantom;
static void framing()
{
  const SspStamp original { 0x0102030405060708ULL, 0x1112131415161718ULL, 257 };
  const auto wire = encode_ssp( original, "abc" );
  CHECK( wire.size() == SSP_TIMING_BYTES + 3 );
  CHECK( wire[0] == 1 && wire[1] == 1 && wire[8] == 8 && wire[9] == 0x11 && wire[16] == 0x18 );
  CHECK( wire[17] == 0 && wire[18] == 0 && wire[19] == 1 && wire[20] == 1 );
  SspStamp decoded;
  CHECK( decode_ssp( wire, decoded ) && decoded.serial == original.serial && decoded.echo == original.echo
         && decoded.hold_ms == original.hold_ms );
  for ( std::size_t n = 0; n < SSP_TIMING_BYTES; ++n ) {
    SspStamp sentinel { 91, 0, 0 };
    CHECK( !decode_ssp( Bytes( n ), sentinel ) && sentinel.serial == 91 );
  }
  auto bad = wire;
  bad[0] = 2;
  CHECK( !decode_ssp( bad, decoded ) );
  bad = encode_ssp( { 1, 0, 0 }, "" );
  bad[20] = 1;
  CHECK( !decode_ssp( bad, decoded ) );
  bad = wire;
  bad[17] = 1;
  CHECK( !decode_ssp( bad, decoded ) );
}
static void roundtrip_and_dwell()
{
  SspTiming a( 65530 ), b( 100 ); // deliberately unrelated clock origins
  auto first = a.prepare( 65530 );
  a.sent( first, 65530 );
  b.received( first, 100 );
  auto reply = b.prepare( 125 );
  CHECK( reply.echo == first.serial && reply.hold_ms == 25 );
  b.sent( reply, 125 );
  a.received( reply, 65620 ); // crosses the legacy 16-bit wrap, not this protocol
  CHECK( a.samples() == 1 && a.srtt() == 65 && a.rttvar() == 32.5 && a.timeout() == 195 );
  a.received( reply, 65621 );
  CHECK( a.samples() == 1 );
  auto second = a.prepare( 65630 );
  a.sent( second, 65630 );
  a.received( { 100, second.serial, 0 }, 65710 );
  CHECK( a.samples() == 2 && std::fabs( a.srtt() - 66.875 ) < 0.001 );
  CHECK( a.timeout() >= 50 && a.timeout() <= 1000 );
}
static void stale_unknown_and_failed()
{
  SspTiming a( 0 );
  const auto failed = a.prepare( 0 ); // no successful local send
  a.received( { 1, failed.serial, 0 }, 50 );
  CHECK( a.samples() == 0 );
  const auto good = a.prepare( 50 );
  a.sent( good, 50 );
  a.received( { 2, good.serial, 100 }, 75 ); // impossible negative network RTT
  CHECK( a.samples() == 0 );
  a.received( { 3, 99999, 0 }, 80 );
  CHECK( a.samples() == 0 );
  const auto held = a.prepare( 80 );
  a.sent( held, 80 );
  // Advance in small increments: timeout is checked per sample, not only per tick.
  a.advance( 10000 );
  a.received( { 4, held.serial, 0 }, 11000 );
  CHECK( a.samples() == 0 );
  CHECK( a.prepare( 12001 ).echo == 0 ); // stale replies are not echoed indefinitely
  bool rejected = false;
  try { a.advance( 12000 ); } catch ( const Error& ) { rejected = true; }
  CHECK( rejected );
}
static void bounded_history_and_migration()
{
  SspTiming a( 0 );
  const auto oldest = a.prepare( 0 );
  a.sent( oldest, 0 );
  SspStamp last;
  for ( std::size_t i = 0; i < SspTiming::HISTORY; ++i ) {
    last = a.prepare( 0 ); // many packets can share a clock tick without aliasing
    a.sent( last, 0 );
  }
  a.received( { 1, oldest.serial, 0 }, 10 );
  CHECK( a.samples() == 0 );
  a.received( { 2, last.serial, 0 }, 20 );
  CHECK( a.samples() == 1 && a.srtt() == 20 );
  const auto prior_path = a.prepare( 20 );
  a.sent( prior_path, 20 );
  a.reset_path();
  a.received( { 3, prior_path.serial, 0 }, 30 );
  CHECK( a.samples() == 1 && !a.has_sample() );
  const auto new_path = a.prepare( 30 );
  CHECK( new_path.serial > prior_path.serial );
  a.sent( new_path, 30 );
  a.received( { 4, new_path.serial, 0 }, 60 );
  CHECK( a.samples() == 2 && a.srtt() == 30 );
  const auto before_sleep = a.prepare( 60 );
  a.sent( before_sleep, 60 );
  constexpr std::uint64_t six_months = 180ULL * 24 * 60 * 60 * 1000;
  a.received( { 5, before_sleep.serial, 0 }, six_months );
  CHECK( a.samples() == 2 && !a.has_sample() );
  CHECK( a.prepare( six_months ).serial > before_sleep.serial );
}
int main()
{
  try {
    framing();
    roundtrip_and_dwell();
    stale_unknown_and_failed();
    bounded_history_and_migration();
    std::cout << "PASS SSP timestamp framing, dwell correction, wrap, history, loss and migration\n";
    return 0;
  } catch ( const std::exception& e ) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
