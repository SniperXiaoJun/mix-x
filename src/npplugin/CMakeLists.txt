include_directories(../../include)
include_directories(../../include/npapi)

add_definitions(-DUNICODE -D_UNICODE -DNOCRYPT -DMIX_BORINGSSL)
add_definitions(-DWIN32 -D_WINDOWS -DXP_WIN)

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
  )

FILE(GLOB 
  common_cpps
  ${CMAKE_SOURCE_DIR}/common/encode_switch.cpp
  ${CMAKE_SOURCE_DIR}/common/certificate_items_parse.cpp
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


#ADD_LIBRARY(
#  npwtbankplugin SHARED
#  
#  npplugin.def
#  ${CMAKE_SOURCE_DIR}/npplugin/npplugin_wtbank.rc
#  
#  ${npplugin_cpps}
#  ${jsoncpp_cpps}
#  ${common_cpps}
#)

#target_link_libraries(npwtbankplugin sqlite3)
#TARGET_LINK_LIBRARIES(npwtbankplugin mix_bssl)
#TARGET_LINK_LIBRARIES(npwtbankplugin smb_base)
#TARGET_LINK_LIBRARIES(npwtbankplugin smb_qtui)
#TARGET_LINK_LIBRARIES(npwtbankplugin Wininet)
#TARGET_LINK_LIBRARIES(npwtbankplugin Crypt32)
#TARGET_LINK_LIBRARIES(npwtbankplugin SetupAPI)

