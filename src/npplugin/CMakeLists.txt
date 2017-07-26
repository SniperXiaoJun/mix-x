include_directories(../../include)
include_directories(../../include/npapi)

add_definitions(-DUNICODE -D_UNICODE -DNOCRYPT -DMIX_BORINGSSL)
add_definitions(-DWIN32 -D_WINDOWS -DXP_WIN)

LINK_DIRECTORIES(
  ${CMAKE_SOURCE_DIR}/../lib
)

FILE(GLOB 
  common_cs 
  )

FILE(GLOB 
  common_cpps
  ${CMAKE_SOURCE_DIR}/common/encode_switch.cpp
  ${CMAKE_SOURCE_DIR}/common/o_all_func_def.c
  ${CMAKE_SOURCE_DIR}/common/certificate_items_parse.cpp
  ${CMAKE_SOURCE_DIR}/common/smcert.cpp
 )
 
 FILE(GLOB 
  jsoncpp_cpps
  ${CMAKE_SOURCE_DIR}/jsoncpp/json_reader.cpp
  ${CMAKE_SOURCE_DIR}/jsoncpp/json_value.cpp
  ${CMAKE_SOURCE_DIR}/jsoncpp/json_writer.cpp
 )

 FILE(GLOB 
  npplugin_cpps

  ${CMAKE_SOURCE_DIR}/npplugin/Common/np_entry.cpp
  ${CMAKE_SOURCE_DIR}/npplugin/Common/npn_gate.cpp
  ${CMAKE_SOURCE_DIR}/npplugin/Common/npp_gate.cpp

  ${CMAKE_SOURCE_DIR}/npplugin/PluginObject.cpp
  ${CMAKE_SOURCE_DIR}/npplugin/Plugin.cpp
  

  ${CMAKE_SOURCE_DIR}/npplugin/EBankSystemDetect.cpp
  ${CMAKE_SOURCE_DIR}/npplugin/EBankSystemDetect_DeviceAndCert.cpp
  ${CMAKE_SOURCE_DIR}/npplugin/EBankSystemDetect_Digest.cpp
  ${CMAKE_SOURCE_DIR}/npplugin/EBankSystemDetect_hosts.cpp
  ${CMAKE_SOURCE_DIR}/npplugin/EBankSystemDetect_Process.cpp
  ${CMAKE_SOURCE_DIR}/npplugin/EBankSystemDetect_System.cpp
  ${CMAKE_SOURCE_DIR}/npplugin/EBankSystemDetect_Internet.cpp
  

  ${CMAKE_SOURCE_DIR}/npplugin/GetPublicIPAddress.cpp
  ${CMAKE_SOURCE_DIR}/npplugin/TimeAPI.cpp
  ${CMAKE_SOURCE_DIR}/npplugin/msclient_api.cpp
  ${CMAKE_SOURCE_DIR}/npplugin/CheckAPI.cpp
  ${CMAKE_SOURCE_DIR}/npplugin/registry.cc
  ${CMAKE_SOURCE_DIR}/npplugin/SSLCon.cpp
  ${CMAKE_SOURCE_DIR}/npplugin/HttpConnect.cpp
  
 )
 
ADD_LIBRARY(
  npwtsmbplugin SHARED
  
  npplugin.def
  ${CMAKE_SOURCE_DIR}/npplugin/npplugin.rc
  
  ${npplugin_cpps}
  ${jsoncpp_cpps}
  ${common_cpps}
)

target_link_libraries(npwtsmbplugin sqlite3)
TARGET_LINK_LIBRARIES(npwtsmbplugin mix_bssl)
TARGET_LINK_LIBRARIES(npwtsmbplugin smb_base)
TARGET_LINK_LIBRARIES(npwtsmbplugin smb_qtui)
TARGET_LINK_LIBRARIES(npwtsmbplugin Wininet)
TARGET_LINK_LIBRARIES(npwtsmbplugin Crypt32)
TARGET_LINK_LIBRARIES(npwtsmbplugin SetupAPI)


ADD_LIBRARY(
  npwtsmbplugin-wtbank SHARED
  
  npplugin.def
  ${CMAKE_SOURCE_DIR}/npplugin/npplugin_wtbank.rc
  
  ${npplugin_cpps}
  ${jsoncpp_cpps}
  ${common_cpps}
)

target_link_libraries(npwtsmbplugin-wtbank sqlite3)
TARGET_LINK_LIBRARIES(npwtsmbplugin-wtbank mix_bssl)
TARGET_LINK_LIBRARIES(npwtsmbplugin-wtbank smb_base)
TARGET_LINK_LIBRARIES(npwtsmbplugin-wtbank smb_qtui)
TARGET_LINK_LIBRARIES(npwtsmbplugin-wtbank Wininet)
TARGET_LINK_LIBRARIES(npwtsmbplugin-wtbank Crypt32)
TARGET_LINK_LIBRARIES(npwtsmbplugin-wtbank SetupAPI)

