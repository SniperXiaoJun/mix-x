include_directories(../../include)


add_definitions(-DUNICODE -D_UNICODE -DNOCRYPT -DMIX_BORINGSSL -DSQLITE_HAS_CODEC -DCODEC_TYPE=CODEC_TYPE_AES256 -DDLL_EXPORTS)


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

#add_subdirectory(x_itemx)

ADD_LIBRARY(
  smb_qtui_win_system SHARED
  
  ${CMAKE_SOURCE_DIR}/smb_qtui_win_system/smb_qtui_win_system.rc
  #${CMAKE_SOURCE_DIR}/smb_qtui_win_system/smb_qtui_win_system.def
  ${CMAKE_SOURCE_DIR}/smb_qtui_win_system/smb_qtui_win_system.cpp
)
TARGET_LINK_LIBRARIES(smb_qtui_win_system smb_base)

add_dependencies(x_all smb_qtui_win_system)











