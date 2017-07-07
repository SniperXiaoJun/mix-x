include_directories(../../include)
include_directories(../../include/npapi)

add_definitions(-DUNICODE -D_UNICODE -DNOCRYPT -DMIX_BORINGSSL)
add_definitions(-DWIN32 -D_WINDOWS -DXP_WIN -D_X86_)

LINK_DIRECTORIES(
  ${CMAKE_SOURCE_DIR}/../lib
)

SET(CMAKE_MFC_FLAG 1)

 FILE(GLOB 
  nptranslucent_cpps

  ${CMAKE_SOURCE_DIR}/nptranslucent/np_entry.cpp
  ${CMAKE_SOURCE_DIR}/nptranslucent/npn_gate.cpp
  ${CMAKE_SOURCE_DIR}/nptranslucent/npp_gate.cpp

  ${CMAKE_SOURCE_DIR}/nptranslucent/PluginObject.cpp
  ${CMAKE_SOURCE_DIR}/nptranslucent/Plugin.cpp
  ${CMAKE_SOURCE_DIR}/nptranslucent/GetMacAddress.cpp
  ${CMAKE_SOURCE_DIR}/nptranslucent/DLDialog.cpp
  ${CMAKE_SOURCE_DIR}/nptranslucent/nptranslucent.rc
 )
 
ADD_LIBRARY(
  nptranslucent SHARED
  
  nptranslucent.def
  ${nptranslucent_cpps}
)

target_link_libraries(nptranslucent sqlite3)
TARGET_LINK_LIBRARIES(nptranslucent mix_bssl)
TARGET_LINK_LIBRARIES(nptranslucent smb_base)
TARGET_LINK_LIBRARIES(nptranslucent smb_qtui)
TARGET_LINK_LIBRARIES(nptranslucent Wininet)
TARGET_LINK_LIBRARIES(nptranslucent Crypt32)
TARGET_LINK_LIBRARIES(nptranslucent SetupAPI)




