include_directories(../../include)

LINK_DIRECTORIES(
  ${CMAKE_SOURCE_DIR}/../lib
)

add_executable(
  x_digest

  x_digest.c
)

target_link_libraries(x_digest mix_bssl)
add_dependencies(x_all x_digest)

