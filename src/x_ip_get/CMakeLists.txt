include_directories(../../include)

LINK_DIRECTORIES(
  ${CMAKE_SOURCE_DIR}/../lib
)

IF(WIN32)
  IF (MSVC)
    IF (MSVC_VERSION EQUAL 1700)
      set(CMAKE_GENERATOR_TOOLSET "v110_xp" CACHE STRING "Platform Toolset" FORCE)
    ELSEIF (MSVC_VERSION EQUAL 1800)
      set(CMAKE_GENERATOR_TOOLSET "v120_xp" CACHE STRING "Platform Toolset" FORCE)
    ELSEIF (MSVC_VERSION EQUAL 1900)
      set(CMAKE_GENERATOR_TOOLSET "v140_xp" CACHE STRING "Platform Toolset" FORCE)
    ENDIF()
  ENDIF(MSVC)
ENDIF(WIN32)

add_executable(
  x_ip_get

  x_ip_get.cpp
  registry.cc
  msclient_api.cpp
)

target_link_libraries(x_ip_get mix_bssl)
add_dependencies(x_all x_ip_get)

