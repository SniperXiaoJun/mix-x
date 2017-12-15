include_directories(../../include)


add_definitions(-DUNICODE -D_UNICODE -DNOCRYPT -DMIX_BORINGSSL)

set(
    ARCH_SOURCES
    #cpu-arm.c
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
  ${CMAKE_SOURCE_DIR}/common/encode_switch.cpp
  ${CMAKE_SOURCE_DIR}/common/smb_cs_verify_chain.cpp
  ${CMAKE_SOURCE_DIR}/common/certificate_items_parse.cpp
 )

LINK_DIRECTORIES(
  ${CMAKE_SOURCE_DIR}/../lib
)

#add_subdirectory(x_itemx)

ADD_LIBRARY(
  smb_base SHARED
  
  smb_base.rc
  smb_base.def
  ${common_cs} 
  ${common_cpps} 
)

target_link_libraries(smb_base sqlite3)
TARGET_LINK_LIBRARIES(smb_base mix_bssl)
TARGET_LINK_LIBRARIES(smb_base Crypt32)
TARGET_LINK_LIBRARIES(smb_base Cryptui)
TARGET_LINK_LIBRARIES(smb_base version)

add_dependencies(x_all smb_base)

add_executable(
  x_dbcs_exec_sql

  x_dbcs_exec_sql.cpp
)
target_link_libraries(x_dbcs_exec_sql smb_base)

add_executable(
  x_dbcs_install_ca_cert

  x_dbcs_install_ca_cert.cpp
)
TARGET_LINK_LIBRARIES(x_dbcs_install_ca_cert smb_base)

add_executable(
  x_dbcs_install_ca_cert_rsa

  x_dbcs_install_ca_cert_rsa.cpp
)
TARGET_LINK_LIBRARIES(x_dbcs_install_ca_cert_rsa smb_base)

add_executable(
  x_dbcs_install_ca_cert_sm2

  x_dbcs_install_ca_cert_sm2.cpp
)
TARGET_LINK_LIBRARIES(x_dbcs_install_ca_cert_sm2 smb_base)

add_executable(
  x_dbcs_enum_certs

  x_dbcs_enum_certs.cpp
)
target_link_libraries(x_dbcs_enum_certs smb_base)
TARGET_LINK_LIBRARIES(x_dbcs_enum_certs SMB_QTUI)

add_executable(
  x_dbcs_verify_der

  x_dbcs_verify_der.cpp
  #${common_cs} 
  #${common_cpps} 
)
target_link_libraries(x_dbcs_verify_der smb_base)

add_executable(
  x_dbcs_show_der

  x_dbcs_show_der.cpp
)
target_link_libraries(x_dbcs_show_der smb_base)
target_link_libraries(x_dbcs_show_der smb_qtui)

add_executable(
  x_dbcs_enum_fileinfo

  x_dbcs_enum_fileinfo.cpp
)
target_link_libraries(x_dbcs_enum_fileinfo smb_base)

add_executable(
  x_dbcs_rw_certs

  x_dbcs_rw_certs.cpp
)
target_link_libraries(x_dbcs_rw_certs smb_base)


ADD_LIBRARY(
  GetKeyInfo SHARED

  GetKeyInfo.rc

  GetKeyInfo.def

  GetKeyInfo.cpp
)
target_link_libraries(GetKeyInfo smb_base)
TARGET_LINK_LIBRARIES(GetKeyInfo SetupAPI)




