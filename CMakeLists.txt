cmake_minimum_required(VERSION 3.22)
project(nanowire VERSION 0.1.0 LANGUAGES CXX)

# nanowire: header-only protocol core (wire definitions, zero-copy views, value builders,
# zero-copy reassembly, runtime dispatch) shared by the read edge (nanoshark) and the craft edge
# (nanocraft). C++23; its only dependency is nanom (header-only), fetched below.

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  set(NANOWIRE_STANDALONE ON)
else()
  set(NANOWIRE_STANDALONE OFF)
endif()

option(NANOWIRE_BUILD_TESTS "Build nanowire tests and register them with CTest" ${NANOWIRE_STANDALONE})
option(NANOWIRE_BUILD_BENCH "Build nanowire benchmarks" ${NANOWIRE_STANDALONE})
option(NANOWIRE_WERROR "Treat warnings as errors (tests/bench only)" OFF)
set(NANOWIRE_SANITIZER "" CACHE STRING "Sanitizers for tests/bench, e.g. 'address,undefined'")

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 12)
  message(FATAL_ERROR "nanowire needs GCC 12 or newer (found ${CMAKE_CXX_COMPILER_VERSION}).")
endif()

if(NANOWIRE_STANDALONE)
  set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
  if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
  endif()
endif()

# ---- nanom (header-only) ------------------------------------------------------------------------
# Pinned commit. For local co-development point FETCHCONTENT_SOURCE_DIR_NANOM at a checkout:
#   cmake -B build -DFETCHCONTENT_SOURCE_DIR_NANOM=/path/to/nanom
# An embedding project that already provides the nanom::nanom target wins (no second copy).
set(NANOWIRE_NANOM_GIT_URL "https://github.com/yoavbendor/nanom.git" CACHE STRING "nanom repository")
set(NANOWIRE_NANOM_GIT_TAG "16f8ec1d1113bb6b99160949d1a9b87dcf88c374" CACHE STRING "nanom commit")
if(NOT TARGET nanom::nanom)
  include(FetchContent)
  FetchContent_Declare(nanom
    GIT_REPOSITORY ${NANOWIRE_NANOM_GIT_URL}
    GIT_TAG ${NANOWIRE_NANOM_GIT_TAG}
    GIT_SHALLOW FALSE)
  # nanom's CMakeLists returns before its own tests/benches when it is not the top-level project,
  # so this only declares the header-only nanom::nanom / nanom::shark targets.
  FetchContent_MakeAvailable(nanom)
endif()

# ---- the library --------------------------------------------------------------------------------
add_library(nanowire INTERFACE)
add_library(nanowire::nanowire ALIAS nanowire)
target_include_directories(nanowire INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)
target_compile_features(nanowire INTERFACE cxx_std_23)
target_link_libraries(nanowire INTERFACE nanom::nanom)
# MSVC's default preprocessor passes __VA_ARGS__ on as one argument, which NANOM_DESCRIBE needs split.
target_compile_options(nanowire INTERFACE $<$<CXX_COMPILER_ID:MSVC>:/Zc:preprocessor>)

include(GNUInstallDirs)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# ---- tests / bench ------------------------------------------------------------------------------
if(NANOWIRE_BUILD_TESTS OR NANOWIRE_BUILD_BENCH)
  add_library(nanowire_dev_flags INTERFACE)
  target_compile_options(nanowire_dev_flags INTERFACE -Wall -Wextra -Wpedantic
    $<$<BOOL:${NANOWIRE_WERROR}>:-Werror>)
  if(NANOWIRE_SANITIZER)
    target_compile_options(nanowire_dev_flags INTERFACE
      -fsanitize=${NANOWIRE_SANITIZER} -fno-omit-frame-pointer -fno-sanitize-recover=all -g)
    target_link_options(nanowire_dev_flags INTERFACE -fsanitize=${NANOWIRE_SANITIZER})
  endif()
endif()

if(NANOWIRE_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
if(NANOWIRE_BUILD_BENCH)
  add_subdirectory(bench)
endif()
