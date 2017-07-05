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
  x_test

  x_test.cpp
)
add_dependencies(x_all x_test)

add_executable(
  x_test_getlocalip

  x_test_getlocalip.cpp
)
add_dependencies(x_all x_test_getlocalip)

