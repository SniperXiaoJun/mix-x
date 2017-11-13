include_directories(../../include)

add_executable(
  x_test_certkeyid

  x_test_certkeyid.cpp
)

target_link_libraries(x_test_certkeyid sqlite3)
TARGET_LINK_LIBRARIES(x_test_certkeyid Crypt32)
add_dependencies(x_all x_test_certkeyid)


include_directories(../../include)

add_executable(
  x_test_csp

  x_test_csp.cpp
)

target_link_libraries(x_test_csp sqlite3)
add_dependencies(x_all x_test_csp)


add_executable(
  x_test_auth_admin

  x_test_auth_admin.cpp
)

add_dependencies(x_all x_test_auth_admin)

add_executable(
  x_test_ssl

  ${CMAKE_SOURCE_DIR}/common/FILE_LOG.c
  ${CMAKE_SOURCE_DIR}/npplugin/registry.cc
  ${CMAKE_SOURCE_DIR}/npplugin/SSLCon.cpp

  x_test_ssl.cpp
)
add_dependencies(x_all x_test_ssl)

TARGET_LINK_LIBRARIES(x_test_ssl Wininet)
TARGET_LINK_LIBRARIES(x_test_ssl Crypt32)

add_executable(
  x_test_getlocalip

  x_test_getlocalip.cpp
)
add_dependencies(x_all x_test_getlocalip)

