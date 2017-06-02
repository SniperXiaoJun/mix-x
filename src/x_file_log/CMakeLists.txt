include_directories(../../include)

add_executable(
  x_file_log

  FILE_LOG.cpp
  x_file_log.c
)

add_dependencies(x_all x_file_log)

