# Session control is above the unchanged draft-01 record protocol.
if(UNIX)
  target_sources(phantom_record PRIVATE remote_session.cc session_offer.cc)
  foreach(name IN ITEMS remote_session session_offer)
    add_executable(phantom_${name}_test ../../tests/phantom/${name}_test.cc)
    target_link_libraries(phantom_${name}_test PRIVATE phantom_record)
    add_test(NAME phantom-${name} COMMAND phantom_${name}_test)
    set_tests_properties(phantom-${name} PROPERTIES TIMEOUT 15)
  endforeach()
endif()

if(PHANTOM_BUILD_SSH_STARTUP)
  add_library(phantom_session_udp STATIC session_udp.cc session_channel.cc)
  target_link_libraries(phantom_session_udp PUBLIC phantom_record)
  target_compile_options(phantom_session_udp PRIVATE -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)
  add_executable(phantom-mosh-server session_server.cc)
  target_link_libraries(phantom-mosh-server PRIVATE phantom_session_udp)
  add_executable(phantom-mosh-probe session_probe.cc)
  target_link_libraries(phantom-mosh-probe PRIVATE phantom_session_udp phantom_ssh_startup)
  add_executable(phantom_session_driver ../../tests/phantom/session_driver.cc)
  target_link_libraries(phantom_session_driver PRIVATE phantom_session_udp phantom_ssh_startup)
  foreach(target IN ITEMS phantom-mosh-server phantom-mosh-probe phantom_session_driver)
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)
  endforeach()
  add_test(NAME phantom-session-process
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/../../tests/phantom/session_process_test.py
      $<TARGET_FILE:phantom-mosh-server> $<TARGET_FILE:phantom_session_driver>)
  set_tests_properties(phantom-session-process PROPERTIES TIMEOUT 30)
  add_test(NAME phantom-session-supervisor
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/../../tests/phantom/session_supervisor_test.py
      $<TARGET_FILE:phantom-mosh-server> $<TARGET_FILE:phantom_session_driver>)
  set_tests_properties(phantom-session-supervisor PROPERTIES TIMEOUT 30)
endif()

if(PHANTOM_BUILD_SSH_STARTUP)
  add_executable(phantom_session_channel_test ../../tests/phantom/session_channel_test.cc)
  target_link_libraries(phantom_session_channel_test PRIVATE phantom_session_udp)
  target_link_options(phantom_session_channel_test PRIVATE "-Wl,--wrap=sendto" "-Wl,--wrap=recvmsg")
  target_compile_options(phantom_session_channel_test PRIVATE -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)
  add_test(NAME phantom-session-channel COMMAND phantom_session_channel_test)
  set_tests_properties(phantom-session-channel PROPERTIES TIMEOUT 30)
  add_executable(phantom_channel_process ../../tests/phantom/channel_process.cc)
  target_link_libraries(phantom_channel_process PRIVATE phantom_session_udp)
  target_compile_options(phantom_channel_process PRIVATE -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)
  add_test(NAME phantom-channel-process
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/../../tests/phantom/session_process_test.py
      $<TARGET_FILE:phantom-mosh-server> $<TARGET_FILE:phantom_channel_process>)
  set_tests_properties(phantom-channel-process PROPERTIES TIMEOUT 30)
endif()

if(PHANTOM_BUILD_SSH_STARTUP)
  add_test(NAME phantom-session-ssh
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/../../tests/phantom/session_ssh_test.py
      $<TARGET_FILE:phantom-mosh-server> $<TARGET_FILE:phantom-mosh-probe> ${PHANTOM_SSH_TEST_ARGUMENTS})
  set_tests_properties(phantom-session-ssh PROPERTIES TIMEOUT 60 SKIP_RETURN_CODE 77)
endif()

# PTY process ownership is a separately testable Linux frontend prerequisite.
# The control-only server/probe deliberately do not launch it yet.
if(PHANTOM_BUILD_SSH_STARTUP)
  add_library(phantom_terminal_pty STATIC terminal_pty.cc)
  target_include_directories(phantom_terminal_pty PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
  target_compile_features(phantom_terminal_pty PUBLIC cxx_std_17)
  if(PHANTOM_SANITIZERS)
    target_compile_options(phantom_terminal_pty PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(phantom_terminal_pty PUBLIC -fsanitize=address,undefined)
  endif()
  target_compile_options(phantom_terminal_pty PRIVATE -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)
  add_executable(phantom_terminal_pty_test ../../tests/phantom/terminal_pty_test.cc)
  target_link_libraries(phantom_terminal_pty_test PRIVATE phantom_terminal_pty)
  target_link_options(phantom_terminal_pty_test PRIVATE "-Wl,--wrap=execv" "-Wl,--wrap=waitpid")
  target_compile_options(phantom_terminal_pty_test PRIVATE -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)
  add_test(NAME phantom-terminal-pty COMMAND phantom_terminal_pty_test)
  set_tests_properties(phantom-terminal-pty PROPERTIES TIMEOUT 15)
endif()
