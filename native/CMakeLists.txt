cmake_minimum_required(VERSION 3.5)
project(ecelgamal)

find_package(Java REQUIRED)
find_package(JNI REQUIRED)
find_package(OpenSSL REQUIRED)

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR} ${OPENSSL_INCLUDE_DIR})

file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/out)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/out)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY  ${CMAKE_CURRENT_SOURCE_DIR}/out)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -std=c++11")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -Wall -O3 -march=native")

add_executable(ore-test test_ore.cpp ore.c ore_blk.c crypto.c oreencodings.c)

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR} ${OPENSSL_INCLUDE_DIR} ${JNI_INCLUDE_DIRS})
add_library(ore-jni-wrapper SHARED ore_jni_wrapper.c ore.c ore_blk.c crypto.c oreencodings.c)

target_link_libraries(ore-test crypto ssl gmp)
target_link_libraries(ore-jni-wrapper crypto ssl gmp)
