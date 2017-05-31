include_directories(../../include)

LINK_DIRECTORIES(
  ${CMAKE_SOURCE_DIR}/../lib
)

add_executable(
  x_md5

  x_md5.cpp
)

target_link_libraries(x_md5 mix_bssl)
add_dependencies(x_all x_md5)

