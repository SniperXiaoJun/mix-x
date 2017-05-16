include_directories(../../include)

ADD_DEFINITIONS(-D_AFXDLL)
add_definitions(-DUNICODE -D_UNICODE -DGM_ECC_512_SUPPORT)

SET(CMAKE_MFC_FLAG 1)


FILE(GLOB x_commontools_cpps "${CMAKE_SOURCE_DIR}/x_commontools/*.cpp")

FILE(GLOB x_commontools_rcs "${CMAKE_SOURCE_DIR}/x_commontools/*.rc")

ADD_EXECUTABLE(
  x_commontools 
  WIN32 
  ${x_commontools_cpps}
  ${x_commontools_rcs}
)