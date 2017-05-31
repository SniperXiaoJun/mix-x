include_directories(../../include)


add_definitions(-DUNICODE -D_UNICODE -DNOCRYPT -DMIX_BORINGSSL)

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
  ${CMAKE_SOURCE_DIR}/common/certificate_items_parse.cpp
 )

LINK_DIRECTORIES(
  ${CMAKE_SOURCE_DIR}/../lib
)

#add_subdirectory(x_itemx)

add_executable(
  x_dbcs

  x_dbcs.c
  ${common_cs} 
  ${common_cpps} 
)

target_link_libraries(x_dbcs sqlite3)
TARGET_LINK_LIBRARIES(x_dbcs mix_bssl)

add_dependencies(x_all x_dbcs)

