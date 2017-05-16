include_directories(../../include)

ADD_DEFINITIONS(-D_AFXDLL)
add_definitions(-DUNICODE -D_UNICODE -DGM_ECC_512_SUPPORT -DNOCRYPT -DMIX_BORINGSSL)

SET(CMAKE_MFC_FLAG 1)


FILE(GLOB x_commontools_cpps "${CMAKE_SOURCE_DIR}/x_commontools/*.cpp")

FILE(GLOB x_commontools_rcs "${CMAKE_SOURCE_DIR}/x_commontools/*.rc")

FILE(GLOB common_cs "${CMAKE_SOURCE_DIR}/common/*.c")
FILE(GLOB common_cpps "${CMAKE_SOURCE_DIR}/common/*.cpp")

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
TARGET_LINK_LIBRARIES(x_commontools swsds)
