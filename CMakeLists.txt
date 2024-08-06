cmake_minimum_required(VERSION 3.20)
project(libpacket C CXX)
add_subdirectory(src)

# Install library headers
install(
    DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include"
    DESTINATION "${CMAKE_INSTALL_PREFIX}"
)
