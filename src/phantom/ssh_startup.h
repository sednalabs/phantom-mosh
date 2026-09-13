// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
#ifndef PHANTOM_MOSH_SSH_STARTUP_H
#define PHANTOM_MOSH_SSH_STARTUP_H

#include "session_offer.h"
#include "startup.h"
#include <chrono>
#include <string>

namespace phantom {
// Local configuration is trusted, not supplied by the remote peer. No arbitrary
// SSH options are exposed: authentication/lifecycle safeguards cannot be undone.
struct SshStartupOptions
{
  std::string destination;               // [user@]host or a trusted SSH configuration alias
  std::string ssh_path = "/usr/bin/ssh"; // absolute executable; never searched in PATH
  std::string server_path = "phantom-mosh-server";
  std::string config_path; // optional trusted -F file; empty uses normal SSH config
  std::chrono::milliseconds timeout = std::chrono::seconds( 10 );
  int cancel_fd = -1; // borrowed readable/HUP descriptor; not read or closed here
};

// Linux/glibc supervisor. Starts a new local process group, closes unrelated
// descriptors in the child and requires bounded output, EOF AND SSH exit zero.
// Every return path kills remaining members of that group and reaps its leader.
// The caller must exclusively own child reaping (no SIGCHLD auto-reap/handler
// stealing this child), and keep cancel_fd open throughout the call.
//
// Runs: exec '<server_path>' '--startup-profile' 'phantom-mosh/v3/draft-01'
// through OpenSSH, never through a local shell. Remote shell tokens are quoted.
// Stderr is discarded rather than exposing remote secret-bearing diagnostics.
// Does not select a UDP host, create a terminal, or guarantee remote cleanup:
// the server must bound the lifetime of unconfirmed sessions independently.
StartupOffer start_over_ssh( const SshStartupOptions& options );

// Selects the session control profile and its address-bound offer. Endpoint
// bytes are accepted only after SSH output, EOF and successful exit validate.
// The advertised server-local address may require an explicit trusted override
// behind NAT; a proxy configuration does not implicitly carry the UDP path.
SessionOffer start_session_over_ssh( const SshStartupOptions& options );
} // namespace phantom
#endif
