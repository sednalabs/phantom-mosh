// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
#ifndef PHANTOM_MOSH_STARTUP_POSIX_H
#define PHANTOM_MOSH_STARTUP_POSIX_H

#include "startup.h"
#include <chrono>

namespace phantom {
// Takes exclusive ownership of fd and closes it on success AND exception.
// fd must be a dedicated pipe or connected stream socket read end, with no
// competing readers or open-file-description aliases. Standard fds are allowed.
// Sets O_NONBLOCK and FD_CLOEXEC. The spawning launcher must already prevent
// unintended inheritance; setting FD_CLOEXEC here cannot fix an earlier leak.
// Requires EOF after exactly one message. timeout is a total 1..120000 ms budget,
// including partial reads and interruptions. No secret enters argv/environment.
// Authentication and SSH exit-status checks belong to the caller, not the pipe.
StartupOffer read_startup_offer_fd( int fd, std::chrono::milliseconds timeout = std::chrono::seconds( 10 ) );
} // namespace phantom
#endif
