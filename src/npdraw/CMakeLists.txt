include_directories(../../include)
include_directories(../../include/npapi)

add_definitions(-DUNICODE -D_UNICODE -DNOCRYPT -DMIX_BORINGSSL)
add_definitions(-DWIN32 -D_WINDOWS -DXP_WIN -D_X86_)

LINK_DIRECTORIES(
  ${CMAKE_SOURCE_DIR}/../lib
)

SET(CMAKE_MFC_FLAG 1)

 FILE(GLOB 
  npruntime_cpps

  ${CMAKE_SOURCE_DIR}/npdraw/np_entry.cpp
  ${CMAKE_SOURCE_DIR}/npdraw/npn_gate.cpp
  ${CMAKE_SOURCE_DIR}/npdraw/npp_gate.cpp

  ${CMAKE_SOURCE_DIR}/npdraw/Plugin.cpp
  ${CMAKE_SOURCE_DIR}/npdraw/PluginObject.cpp
  ${CMAKE_SOURCE_DIR}/npdraw/npdraw.rc
 )
 
ADD_LIBRARY(
  npdraw SHARED
  
  npdraw.def
  ${npruntime_cpps}
)

TARGET_LINK_LIBRARIES(npdraw GDIPlus)


