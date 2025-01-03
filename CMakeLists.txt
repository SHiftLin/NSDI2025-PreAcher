cmake_minimum_required(VERSION 3.16)

project(PreAcher)
set(CMAKE_CXX_STANDARD 17)

include(FetchContent)

FetchContent_Declare(
        cppcodec
        GIT_REPOSITORY https://github.com/tplgy/cppcodec.git
)
FetchContent_MakeAvailable(cppcodec)

add_library(${PROJECT_NAME} STATIC
        src/PreAcher.cpp
        src/PreAcher_crypto.cpp)

target_include_directories(PreAcher PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include" cppcodec)
target_link_libraries(PreAcher sodium ssl crypto cppcodec)

add_subdirectory(test EXCLUDE_FROM_ALL)