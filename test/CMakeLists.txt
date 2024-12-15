include(FetchContent)

FetchContent_Declare(
        json
        GIT_REPOSITORY https://github.com/nlohmann/json
        GIT_TAG v3.11.3
)
FetchContent_MakeAvailable(json)

add_executable(server server.cpp)
target_include_directories(server PRIVATE PreAcher cppcodec)
target_link_libraries(server PreAcher workflow pthread nlohmann_json::nlohmann_json cppcodec)

add_executable(cdn cdn.cpp)
target_include_directories(cdn PRIVATE PreAcher cppcodec)
target_link_libraries(cdn PreAcher workflow pthread nlohmann_json::nlohmann_json cppcodec)