cmake_minimum_required(VERSION 3.16)

project(EncryptionAlgorithmRGR LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(encryption_rgr
    src/main.cpp
    src/core/dynamic_library.cpp
    src/core/cipher_module.cpp
)

add_library(cipher_hill SHARED
    src/ciphers/hill/hill_module.cpp
)

target_include_directories(cipher_hill PRIVATE include)
target_compile_definitions(cipher_hill PRIVATE CIPHER_MODULE_BUILD)
set_target_properties(cipher_hill PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/modules"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/modules"
)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)

add_library(cipher_elgamal SHARED
    src/ciphers/elgamal/elgamal_module.cpp
)

target_include_directories(cipher_elgamal PRIVATE include)
target_compile_definitions(cipher_elgamal PRIVATE CIPHER_MODULE_BUILD)
target_link_libraries(cipher_elgamal PRIVATE OpenSSL::Crypto)
set_target_properties(cipher_elgamal PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/modules"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/modules"
)

target_include_directories(encryption_rgr PRIVATE
    include
    src
)

if(UNIX AND NOT APPLE)
    target_link_libraries(encryption_rgr PRIVATE ${CMAKE_DL_LIBS})
endif()

target_compile_options(encryption_rgr PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-Wpedantic>
)

target_compile_options(cipher_hill PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-Wpedantic>
)

target_compile_options(cipher_elgamal PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-Wpedantic>
)
