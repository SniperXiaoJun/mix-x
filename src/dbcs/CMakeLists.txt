include_directories(../../include)



set(
    ARCH_SOURCES
    #cpu-arm.c
)


#add_subdirectory(x_itemx)

add_library(
  dbcs

  dbcs.cpp

  ${ARCH_SOURCES}
  
#  $<TARGET_OBJECTS:x_itemx>
)

add_executable(
  x_dbcs

  x_dbcs.c
)

target_link_libraries(x_dbcs dbcs)
target_link_libraries(x_dbcs sqlite3)

add_dependencies(x_all x_dbcs)

