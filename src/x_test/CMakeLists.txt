include_directories(../../include)

add_executable(
  x_test

  x_test.cpp
)

target_link_libraries(x_test sqlite3)
add_dependencies(x_all x_test)


include_directories(../../include)

add_executable(
  x_test_csp

  x_test_csp.cpp
)

target_link_libraries(x_test_csp sqlite3)
add_dependencies(x_all x_test_csp)

