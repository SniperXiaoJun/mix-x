include_directories(../../include)

add_executable(
  x_testgdi
  x_testgdi.rc
  x_testgdi.cpp
)

TARGET_LINK_LIBRARIES(x_testgdi GDIPlus)

