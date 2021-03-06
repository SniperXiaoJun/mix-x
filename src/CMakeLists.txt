cmake_minimum_required (VERSION 2.8.10)

project (mix-x)

set(CompilerFlags
        CMAKE_CXX_FLAGS
        CMAKE_CXX_FLAGS_DEBUG
        CMAKE_CXX_FLAGS_RELEASE
        CMAKE_C_FLAGS
        CMAKE_C_FLAGS_DEBUG
        CMAKE_C_FLAGS_RELEASE
        )
foreach(CompilerFlag ${CompilerFlags})
  string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
endforeach()

foreach(CompilerFlag ${CompilerFlags})
  string(REPLACE "/MDd" "/MTd" ${CompilerFlag} "${${CompilerFlag}}")
endforeach()

##
add_custom_target(x_all)

##
add_subdirectory(sqlite)
add_subdirectory(dbcs)
add_subdirectory(npplugin)
add_subdirectory(npsafeinput)
add_subdirectory(nptranslucent)
add_subdirectory(npruntime)
add_subdirectory(npdraw)
add_subdirectory(smb_cs_log)
add_subdirectory(smb_cs_secure)
add_subdirectory(smb_cs_secure_log)
add_subdirectory(smb_qtui_win_system)
add_subdirectory(npwtsmbplugin)


##
add_subdirectory(x_test)
add_subdirectory(x_commontools)
add_subdirectory(x_digest)
add_subdirectory(x_process_get)
add_subdirectory(x_process_killbyname)
add_subdirectory(x_ip_get)
add_subdirectory(x_file_log)
add_subdirectory(x_testgdi)
add_subdirectory(x_test_activex)
add_subdirectory(x_file_copy)
add_subdirectory(x_process_turn)



