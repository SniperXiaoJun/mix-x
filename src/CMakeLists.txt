cmake_minimum_required (VERSION 2.8.10)

project (mix-x)

##
add_custom_target(x_all)

##
add_subdirectory(sqlite)
add_subdirectory(dbcs)

##
add_subdirectory(x_test)
add_subdirectory(x_commontools)

