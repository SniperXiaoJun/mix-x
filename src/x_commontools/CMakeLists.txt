include_directories(../../include)

ADD_DEFINITIONS(-D_AFXDLL)
SET(CMAKE_MFC_FLAG 1)

ADD_EXECUTABLE(
  x_commontools 
  WIN32 
  ./*.cpp
  ./*.rc
)