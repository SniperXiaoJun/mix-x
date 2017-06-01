include_directories(../../include)

LINK_DIRECTORIES(
  ${CMAKE_SOURCE_DIR}/../lib
)

add_executable(
  x_ip_get

  x_ip_get.cpp
  registry.cc
  msclient_api.cpp
)

target_link_libraries(x_ip_get mix_bssl)
add_dependencies(x_all x_ip_get)

