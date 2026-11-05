# The record/session library stays standalone. SSP is an explicit Linux opt-in
# against an Autotools build of the SAME checkout (config.h, protobufs, archives).
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" OR NOT TARGET phantom_session_udp)
  message(FATAL_ERROR "PHANTOM_BUILD_SSP requires the Linux session channel")
endif()
set(PHANTOM_MOSH_BUILD_DIR "" CACHE PATH "Configured and built Mosh tree for SSP integration")
get_filename_component(PHANTOM_SOURCE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
if(NOT PHANTOM_MOSH_BUILD_DIR)
  message(FATAL_ERROR "Set PHANTOM_MOSH_BUILD_DIR to the Autotools build of this checkout; see docs/phantom/ssp.md")
endif()
set(SSP_ARCHIVES)
foreach(component statesync terminal network crypto protobufs util)
  if(component STREQUAL "protobufs")
    set(archive "${PHANTOM_MOSH_BUILD_DIR}/src/protobufs/libmoshprotos.a")
  else()
    set(archive "${PHANTOM_MOSH_BUILD_DIR}/src/${component}/libmosh${component}.a")
  endif()
  if(NOT EXISTS "${archive}")
    message(FATAL_ERROR "Build the inherited Mosh libraries first: missing ${archive}")
  endif()
  list(APPEND SSP_ARCHIVES "${archive}")
endforeach()
if(NOT EXISTS "${PHANTOM_MOSH_BUILD_DIR}/src/include/config.h" OR
   NOT EXISTS "${PHANTOM_MOSH_BUILD_DIR}/src/protobufs/transportinstruction.pb.h")
  message(FATAL_ERROR "The SSP build requires generated config.h and protobuf headers from the same checkout")
endif()
find_package(PkgConfig REQUIRED)
pkg_check_modules(SSP_PROTOBUF REQUIRED IMPORTED_TARGET protobuf)
pkg_check_modules(SSP_TINFO REQUIRED IMPORTED_TARGET tinfo)
find_package(ZLIB REQUIRED)
add_library(phantom_ssp STATIC ssp_timing.cc ssp_connection.cc)
# SspTransport is a public template: its consumers need the inherited engine
# archives and generated-header/dependency usage requirements as well.
target_link_libraries(phantom_ssp PUBLIC phantom_session_udp ${SSP_ARCHIVES}
  PkgConfig::SSP_PROTOBUF PkgConfig::SSP_TINFO ZLIB::ZLIB OpenSSL::Crypto)
target_include_directories(phantom_ssp PUBLIC
  "${PHANTOM_MOSH_BUILD_DIR}/src/include"
  "${PHANTOM_MOSH_BUILD_DIR}" "${PHANTOM_SOURCE_ROOT}")
target_compile_options(phantom_ssp PRIVATE -Wall -Wextra -Wpedantic -Werror)
foreach(test timing connection convergence)
  add_executable(phantom_ssp_${test}_test "../../tests/phantom/ssp_${test}_test.cc")
  target_link_libraries(phantom_ssp_${test}_test PRIVATE phantom_ssp)
  target_compile_options(phantom_ssp_${test}_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
  add_test(NAME phantom-ssp-${test} COMMAND phantom_ssp_${test}_test)
  set_tests_properties(phantom-ssp-${test} PROPERTIES TIMEOUT 60)
endforeach()
# Keep the convergence test dependent only on phantom_ssp, so it also checks
# that downstream consumers inherit the complete compile/link interface.
target_link_options(phantom_ssp_convergence_test PRIVATE "-Wl,--wrap=sendto")

add_executable(phantom-mosh-terminal-server terminal_server.cc)
target_link_libraries(phantom-mosh-terminal-server PRIVATE phantom_ssp phantom_terminal_pty)
target_compile_options(phantom-mosh-terminal-server PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_executable(phantom-mosh-terminal terminal_client.cc)
target_link_libraries(phantom-mosh-terminal PRIVATE phantom_ssp phantom_ssh_startup)
target_compile_options(phantom-mosh-terminal PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_executable(phantom_terminal_idle_driver ../../tests/phantom/terminal_idle_driver.cc)
target_link_libraries(phantom_terminal_idle_driver PRIVATE phantom_ssp phantom_ssh_startup)
target_compile_options(phantom_terminal_idle_driver PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME phantom-terminal-ssh
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/../../tests/phantom/terminal_ssh_test.py
    $<TARGET_FILE:phantom-mosh-terminal-server> $<TARGET_FILE:phantom-mosh-terminal>
    $<TARGET_FILE:phantom-mosh-server> $<TARGET_FILE:phantom-mosh-probe>
    $<TARGET_FILE:phantom_terminal_idle_driver> ${PHANTOM_SSH_TEST_ARGUMENTS})
set_tests_properties(phantom-terminal-ssh PROPERTIES TIMEOUT 60 SKIP_RETURN_CODE 77)
