// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef PHANTOM_MOSH_SSP_TEST_H
#define PHANTOM_MOSH_SSP_TEST_H
#include <stdexcept>
#include <string>
inline void ssp_check( bool result, const char* expression, int line )
{
  if ( !result )
    throw std::runtime_error( std::to_string( line ) + ": " + expression );
}
#define CHECK( x ) ssp_check( static_cast<bool>( x ), #x, __LINE__ )
#endif
