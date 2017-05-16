include_directories(../../include)

add_executable(
  x_test

  x_test.c
)

target_link_libraries(x_test sqlite3)
add_dependencies(x_all x_test)

