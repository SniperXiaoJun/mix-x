include_directories(../../include)
include_directories(../../include/npapi)

add_definitions(-DUNICODE -D_UNICODE -DNOCRYPT -DMIX_BORINGSSL)
add_definitions(-DWIN32 -D_WINDOWS -DXP_WIN -D_X86_)

LINK_DIRECTORIES(
  ${CMAKE_SOURCE_DIR}/../lib
)

SET(CMAKE_MFC_FLAG 1)

 FILE(GLOB 
  npsafeinput_cpps

  ${CMAKE_SOURCE_DIR}/npsafeinput/np_entry.cpp
  ${CMAKE_SOURCE_DIR}/npsafeinput/npn_gate.cpp
  ${CMAKE_SOURCE_DIR}/npsafeinput/npp_gate.cpp

  ${CMAKE_SOURCE_DIR}/npsafeinput/PluginObject.cpp
  ${CMAKE_SOURCE_DIR}/npsafeinput/Plugin.cpp
  ${CMAKE_SOURCE_DIR}/npsafeinput/GetMacAddress.cpp
  ${CMAKE_SOURCE_DIR}/npsafeinput/DLDialog.cpp
  ${CMAKE_SOURCE_DIR}/npsafeinput/npsafeinput.rc
 )
 
ADD_LIBRARY(
  npsafeinput SHARED
  
  npsafeinput.def
  ${npsafeinput_cpps}
)

target_link_libraries(npsafeinput sqlite3)
TARGET_LINK_LIBRARIES(npsafeinput mix_bssl)
TARGET_LINK_LIBRARIES(npsafeinput smb_base)
TARGET_LINK_LIBRARIES(npsafeinput smb_qtui)
TARGET_LINK_LIBRARIES(npsafeinput Wininet)
TARGET_LINK_LIBRARIES(npsafeinput Crypt32)
TARGET_LINK_LIBRARIES(npsafeinput SetupAPI)




