include_directories(../../include)

LINK_DIRECTORIES(
  ${CMAKE_SOURCE_DIR}/../lib
)

add_executable(
  x_process_killbyname

  x_process_killbyname.cpp
)

target_link_libraries(x_process_killbyname mix_bssl)
add_dependencies(x_all x_process_killbyname)

