cmake_minimum_required(VERSION 3.12)
project(libpacket C)

option(LIBPACKET_BUILD_TESTS "Build libpacket tests" ON)

add_subdirectory(src)

if (LIBPACKET_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Install library headers
install(
    DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include"
    DESTINATION "${CMAKE_INSTALL_PREFIX}"
)
