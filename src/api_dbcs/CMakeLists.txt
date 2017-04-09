include_directories(../../include)

if(APPLE)
  if (${ARCH} STREQUAL "x86")

  endif()
elseif(UNIX)
  if (${ARCH} STREQUAL "aarch64")

  elseif (${ARCH} STREQUAL "arm")

  elseif (${ARCH} STREQUAL "x86")

  else()

  endif()
else()
  if (CMAKE_CL_64)

  else()

  endif()
  
endif()

if (${ARCH} STREQUAL "x86_64")
  set(
    CRYPTO_ARCH_SOURCES

    #cpu-intel.c
  )
endif()

if (${ARCH} STREQUAL "x86")
  set(
    CRYPTO_ARCH_SOURCES

    #cpu-intel.c
  )
endif()

if (${ARCH} STREQUAL "arm")
  set(
    CRYPTO_ARCH_SOURCES

    #cpu-arm.c
    #cpu-arm-asm.S
  )
endif()

if (${ARCH} STREQUAL "aarch64")
  set(
    CRYPTO_ARCH_SOURCES

    #cpu-arm.c
  )
endif()

#add_subdirectory(x_itemx)

add_library(
  api_dbcs

  api_dbcs.cpp

  ${CRYPTO_ARCH_SOURCES}

#  $<TARGET_OBJECTS:x_itemx>
)

add_executable(
  x_test_dbcs

  x_test_dbcs.c
)

target_link_libraries(x_test_dbcs api_dbcs)
add_dependencies(x_tests x_test_dbcs)

