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

  ${CMAKE_SOURCE_DIR}/npruntime/np_entry.cpp
  ${CMAKE_SOURCE_DIR}/npruntime/npn_gate.cpp
  ${CMAKE_SOURCE_DIR}/npruntime/npp_gate.cpp

  ${CMAKE_SOURCE_DIR}/npruntime/Plugin.cpp
  ${CMAKE_SOURCE_DIR}/npruntime/nprt.rc
 )
 
ADD_LIBRARY(
  npruntime SHARED
  
  nprt.def
  ${npruntime_cpps}
)

target_link_libraries(npruntime sqlite3)
TARGET_LINK_LIBRARIES(npruntime mix_bssl)
TARGET_LINK_LIBRARIES(npruntime smb_base)
TARGET_LINK_LIBRARIES(npruntime smb_qtui)
TARGET_LINK_LIBRARIES(npruntime Wininet)
TARGET_LINK_LIBRARIES(npruntime Crypt32)
TARGET_LINK_LIBRARIES(npruntime SetupAPI)




