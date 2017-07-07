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
  ${CMAKE_SOURCE_DIR}/nptranslucent/nptranslucent.rc

  ${CMAKE_SOURCE_DIR}/nptranslucent/BackDialogBase.cpp
  ${CMAKE_SOURCE_DIR}/nptranslucent/CtrlDemoBackDialog.cpp
  ${CMAKE_SOURCE_DIR}/nptranslucent/CtrlDemoForeDialog.cpp
  ${CMAKE_SOURCE_DIR}/nptranslucent/DemoBackDialog.cpp
  ${CMAKE_SOURCE_DIR}/nptranslucent/DemoForeDialog.cpp
  ${CMAKE_SOURCE_DIR}/nptranslucent/DialogSimple.cpp
  ${CMAKE_SOURCE_DIR}/nptranslucent/explorer.cpp
  ${CMAKE_SOURCE_DIR}/nptranslucent/ForeDialogBase.cpp
 )
 
ADD_LIBRARY(
  nptranslucent SHARED
  
  nptranslucent.def
  ${nptranslucent_cpps}
)




