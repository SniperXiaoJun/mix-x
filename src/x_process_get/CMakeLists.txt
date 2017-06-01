include_directories(../../include)

LINK_DIRECTORIES(
  ${CMAKE_SOURCE_DIR}/../lib
)

add_executable(
  x_process_get

  x_process_get.c
)

target_link_libraries(x_process_get mix_bssl)
add_dependencies(x_all x_process_get)

