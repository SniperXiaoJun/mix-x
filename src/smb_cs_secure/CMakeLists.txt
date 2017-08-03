include_directories(../../include)


add_definitions(-DUNICODE -D_UNICODE -DNOCRYPT -DMIX_BORINGSSL -DSQLITE_HAS_CODEC)


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

add_library(
  sqlite3secure

  ${CMAKE_SOURCE_DIR}/sqlite/sqlite3secure.c

  ${ARCH_SOURCES}

#  $<TARGET_OBJECTS:x_itemx>
)

set(
    ARCH_SOURCES
    #cpu-arm.c
)


LINK_DIRECTORIES(
  ${CMAKE_SOURCE_DIR}/../lib
)

FILE(GLOB 
  common_cs 
  ${CMAKE_SOURCE_DIR}/common/FILE_LOG.c 
  ${CMAKE_SOURCE_DIR}/common/modp_b64.c 
  ${CMAKE_SOURCE_DIR}/common/o_all_func_def.c 
  ${CMAKE_SOURCE_DIR}/common/openssl_func_def.c 
  )

FILE(GLOB 
  common_cpps
  ${CMAKE_SOURCE_DIR}/common/smb_dev.cpp
  ${CMAKE_SOURCE_DIR}/common/smb_cs.cpp
  ${CMAKE_SOURCE_DIR}/common/smcert.cpp
  ${CMAKE_SOURCE_DIR}/common/smb_cs_verify_chain.cpp
  ${CMAKE_SOURCE_DIR}/common/certificate_items_parse.cpp
 )

LINK_DIRECTORIES(
  ${CMAKE_SOURCE_DIR}/../lib
)

#add_subdirectory(x_itemx)

ADD_LIBRARY(
  smb_base_secure SHARED
  
  ${CMAKE_SOURCE_DIR}/dbcs/smb_base.rc
  ${CMAKE_SOURCE_DIR}/dbcs/smb_base.def

  ${common_cs} 
  ${common_cpps} 
)

target_link_libraries(smb_base_secure sqlite3secure)
TARGET_LINK_LIBRARIES(smb_base_secure mix_bssl)
TARGET_LINK_LIBRARIES(smb_base_secure Crypt32)
TARGET_LINK_LIBRARIES(smb_base_secure Cryptui)
TARGET_LINK_LIBRARIES(smb_base_secure version)

add_dependencies(x_all smb_base_secure)











