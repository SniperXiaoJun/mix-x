include_directories(../../include)

set(
    ARCH_SOURCES

    #cpu-arm.c
)


#add_subdirectory(x_itemx)

add_library(
  sqlite3

  sqlite3.c

  ${ARCH_SOURCES}

#  $<TARGET_OBJECTS:x_itemx>
)

add_executable(
  x_sqlite

  x_sqlite.c
)

target_link_libraries(x_sqlite sqlite3)
add_dependencies(x_all x_sqlite)

