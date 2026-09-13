// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
#ifndef PHANTOM_MOSH_SSP_TRANSPORT_H
#define PHANTOM_MOSH_SSP_TRANSPORT_H

#include "ssp_connection.h"
#include "src/network/networktransport-impl.h"
#include <algorithm>
#include <utility>

namespace phantom {
// Reuse upstream's state/diff/ACK engine, not a parallel implementation of SSP.
// service() shares one caller-supplied clock across receive, RTT and send timers.
template<class MyState, class RemoteState>
class SspTransport : public Network::Transport<MyState, RemoteState, SspConnection>
{
  using Base = Network::Transport<MyState, RemoteState, SspConnection>;

public:
  SspTransport( MyState& local, RemoteState& remote, std::unique_ptr<SessionChannel> channel,
                std::uint64_t now )
    : Base( local, remote, Network::ConnectionInit {}, std::move( channel ), now )
  {}
  std::size_t service( std::uint64_t now )
  {
    auto& connection = Base::get_connection();
    connection.service( now );
    std::size_t fragments = 0;
    while ( connection.pending() ) {
      Base::recv();
      ++fragments;
    }
    Base::tick();
    return fragments;
  }
  int wait_time()
  {
    return std::min( Base::wait_time(), Base::get_connection().wait_time() );
  }
  ChannelState state() const noexcept { return Base::get_connection().state(); }
  ChannelEnd end_reason() const noexcept { return Base::get_connection().end_reason(); }
  const SspTiming& timing() const noexcept { return Base::get_connection().timing(); }
  void rebind( SessionSocket&& socket, std::uint64_t now )
  {
    Base::get_connection().rebind( std::move( socket ), now );
  }
  // First finish SSP shutdown/ACK exchange; this separately closes the channel.
  void start_channel_close( std::uint64_t now ) { Base::get_connection().start_close( now ); }
  void stop() noexcept { Base::get_connection().stop(); }

private:
  using Base::get_connection;
  using Base::get_key; // bootstrap material is not recoverable from this backend
  using Base::port;
  using Base::recv;
  using Base::tick;
};
} // namespace phantom
#endif
