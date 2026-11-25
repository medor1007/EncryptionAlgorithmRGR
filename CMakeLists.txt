cmake_minimum_required(VERSION 3.16)

project(EncryptionAlgorithmRGR LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(CMAKE_CONFIGURATION_TYPES)
    set(APP_RUNTIME_DIRECTORY "${CMAKE_BINARY_DIR}/$<CONFIG>")
    set(MODULE_RUNTIME_DIRECTORY "${CMAKE_BINARY_DIR}/$<CONFIG>/modules")
else()
    set(APP_RUNTIME_DIRECTORY "${CMAKE_BINARY_DIR}")
    set(MODULE_RUNTIME_DIRECTORY "${CMAKE_BINARY_DIR}/modules")
endif()

add_executable(encryption_rgr
    src/main.cpp
    src/core/dynamic_library.cpp
    src/core/cipher_module.cpp
    src/core/command_line.cpp
    src/core/password_auth.cpp
)
set_target_properties(encryption_rgr PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${APP_RUNTIME_DIRECTORY}"
)

add_library(cipher_hill SHARED
    src/ciphers/hill/hill_module.cpp
)

target_include_directories(cipher_hill PRIVATE include)
target_compile_definitions(cipher_hill PRIVATE CIPHER_MODULE_BUILD)
set_target_properties(cipher_hill PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${MODULE_RUNTIME_DIRECTORY}"
    RUNTIME_OUTPUT_DIRECTORY "${MODULE_RUNTIME_DIRECTORY}"
)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)
target_link_libraries(encryption_rgr PRIVATE OpenSSL::Crypto)
target_link_libraries(cipher_hill PRIVATE OpenSSL::Crypto)

add_library(cipher_elgamal SHARED
    src/ciphers/elgamal/elgamal_module.cpp
)

target_include_directories(cipher_elgamal PRIVATE include)
target_compile_definitions(cipher_elgamal PRIVATE CIPHER_MODULE_BUILD)
target_link_libraries(cipher_elgamal PRIVATE OpenSSL::Crypto)
set_target_properties(cipher_elgamal PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${MODULE_RUNTIME_DIRECTORY}"
    RUNTIME_OUTPUT_DIRECTORY "${MODULE_RUNTIME_DIRECTORY}"
)

target_include_directories(encryption_rgr PRIVATE
    include
    src
)

if(UNIX AND NOT APPLE)
    target_link_libraries(encryption_rgr PRIVATE ${CMAKE_DL_LIBS})
endif()

function(enable_strict_warnings target_name)
    target_compile_options(${target_name} PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-Wpedantic;-Werror>
        $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX;/utf-8>
    )
endfunction()

enable_strict_warnings(encryption_rgr)
enable_strict_warnings(cipher_hill)
enable_strict_warnings(cipher_elgamal)

include(CTest)
if(BUILD_TESTING)
    target_compile_definitions(cipher_hill PRIVATE CIPHER_MODULE_TESTING)
    target_compile_definitions(cipher_elgamal PRIVATE CIPHER_MODULE_TESTING)

    add_executable(crypto_tests
        tests/cipher_module_test.cpp
        src/core/dynamic_library.cpp
        src/core/cipher_module.cpp
    )
    target_include_directories(crypto_tests PRIVATE
        include
        src
    )
    enable_strict_warnings(crypto_tests)
    if(UNIX AND NOT APPLE)
        target_link_libraries(crypto_tests PRIVATE ${CMAKE_DL_LIBS})
    endif()
    add_dependencies(crypto_tests cipher_hill cipher_elgamal)
    add_test(NAME cipher_modules_round_trip
        COMMAND crypto_tests
            $<TARGET_FILE:cipher_hill>
            $<TARGET_FILE:cipher_elgamal>
    )
    set_tests_properties(cipher_modules_round_trip PROPERTIES TIMEOUT 120)

    add_executable(password_auth_test
        tests/password_auth_test.cpp
        src/core/password_auth.cpp
    )
    target_include_directories(password_auth_test PRIVATE src)
    target_link_libraries(password_auth_test PRIVATE OpenSSL::Crypto)
    target_compile_options(password_auth_test PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-Wpedantic>
    )
    add_test(NAME password_authentication COMMAND password_auth_test)
    enable_strict_warnings(password_auth_test)

    add_executable(command_line_test
        tests/command_line_test.cpp
        src/core/command_line.cpp
    )
    target_include_directories(command_line_test PRIVATE src)
    enable_strict_warnings(command_line_test)
    add_test(NAME command_line_validation COMMAND command_line_test)
endif()
