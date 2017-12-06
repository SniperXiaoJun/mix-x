include_directories(../../include)

LINK_DIRECTORIES(
  ${CMAKE_SOURCE_DIR}/../lib
)

add_executable(
  x_process_turn

  x_process_turn.rc

  x_process_turn.cpp
)

target_link_libraries(x_process_turn mix_bssl)
add_dependencies(x_all x_process_turn)

