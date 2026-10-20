cmake_minimum_required(VERSION 3.13)
project(rak_fuzzy VERSION 1.0.0 LANGUAGES CXX)

# The same source tree builds the shared library on Linux
# (librak_fuzzy.so) and on Windows (rak_fuzzy.dll).
#
#   cmake -B build -DCMAKE_BUILD_TYPE=Release
#   cmake --build build
#   ctest --test-dir build
#
# Options:
#   -DRAK_FUZZY_ENABLE_TLSH=OFF   build without the TLSH-like digest
#   -DRAK_FUZZY_SANITIZE=ON       build with address and UB sanitizers

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(RAK_FUZZY_ENABLE_TLSH "Build the TLSH-like digest" ON)
option(RAK_FUZZY_SANITIZE "Build with address and undefined behaviour sanitizers" OFF)

set(RAK_FUZZY_SOURCES
    src/ctph.cpp
    src/tlsh_like.cpp
    src/cluster.cpp
    src/api.cpp)

add_library(rak_fuzzy SHARED ${RAK_FUZZY_SOURCES})
target_include_directories(rak_fuzzy PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
target_compile_definitions(rak_fuzzy PRIVATE RAK_FUZZY_BUILDING)
if(RAK_FUZZY_ENABLE_TLSH)
  target_compile_definitions(rak_fuzzy PRIVATE RAK_FUZZY_ENABLE_TLSH)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(rak_fuzzy PRIVATE -Wall -Wextra)
endif()

if(RAK_FUZZY_SANITIZE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(rak_fuzzy PUBLIC -g -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(rak_fuzzy PUBLIC -fsanitize=address,undefined)
endif()

if(WIN32)
  set_target_properties(rak_fuzzy PROPERTIES PREFIX "" SUFFIX ".dll")
else()
  set_target_properties(rak_fuzzy PROPERTIES PREFIX "lib" SUFFIX ".so")
endif()

# Keep the library and the test binaries in the same directory so that the
# tests find the shared library at run time.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

enable_testing()

foreach(test_name test_ctph test_cluster)
  add_executable(${test_name} tests/${test_name}.cpp)
  target_link_libraries(${test_name} PRIVATE rak_fuzzy)
  if(WIN32)
    # GetProcessMemoryInfo() lives in psapi on Windows.
    target_link_libraries(${test_name} PRIVATE psapi)
  endif()
  add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

install(TARGETS rak_fuzzy
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)
install(FILES include/rak_fuzzy.h DESTINATION include)
