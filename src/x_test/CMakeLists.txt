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

