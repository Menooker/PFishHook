cmake_minimum_required(VERSION 3.5)
project(PFishHook)
set(LIB_NAME PFishHook)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
add_subdirectory(${PROJECT_SOURCE_DIR}/3rdparty/zydis)
include_directories(
    ${PROJECT_SOURCE_DIR}/3rdparty/zydis
    ${PROJECT_SOURCE_DIR}/3rdparty/zydis/include
    ${PROJECT_SOURCE_DIR}/
    )

add_library(${LIB_NAME} inline_hook.cpp)
target_link_libraries(${LIB_NAME} Zydis)
add_dependencies(${LIB_NAME} Zydis)
add_executable(hooker-test hooktest.cpp)
target_link_libraries(hooker-test ${LIB_NAME} Zydis)
