include_directories(../../include)

##ADD_DEFINITIONS(-D_AFXDLL)
add_definitions(-DUNICODE -D_UNICODE -DGM_ECC_512_SUPPORT -DNOCRYPT -DMIX_BORINGSSL)

SET(CMAKE_MFC_FLAG 1)

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

FILE(GLOB x_commontools_cpps "${CMAKE_SOURCE_DIR}/x_commontools/*.cpp")

FILE(GLOB x_commontools_rcs "${CMAKE_SOURCE_DIR}/x_commontools/*.rc")

FILE(GLOB 
  common_cs 
  ${CMAKE_SOURCE_DIR}/common/FILE_LOG.c 
  ${CMAKE_SOURCE_DIR}/common/gm-ecc-512.c 
  ${CMAKE_SOURCE_DIR}/common/gm-hash-bit.c 
  ${CMAKE_SOURCE_DIR}/common/modp_b64.c 
  ${CMAKE_SOURCE_DIR}/common/o_all_func_def.c 
  ${CMAKE_SOURCE_DIR}/common/openssl_func_def.c 
  ${CMAKE_SOURCE_DIR}/common/openssl_func_def_gm_ecc_512.c)
FILE(GLOB 
  common_cpps
  ${CMAKE_SOURCE_DIR}/common/encode_switch.cpp 
  )

LINK_DIRECTORIES(
  ${CMAKE_SOURCE_DIR}/../lib
)

ADD_EXECUTABLE(
  x_commontools 
  WIN32 
  ${x_commontools_cpps}
  ${x_commontools_rcs}
  
  ${common_cs}
  ${common_cpps}
)

TARGET_LINK_LIBRARIES(x_commontools mix_bssl)
