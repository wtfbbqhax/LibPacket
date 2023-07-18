cmake_minimum_required(VERSION 3.12)
project(libpacket_tests)

# Locate and include Google Test
find_package(GTest REQUIRED)
include(GoogleTest)

# Create an executable for the tests
add_executable(check_packet_accessors check_packet_accessors.cpp)
target_link_libraries(check_packet_accessors PRIVATE GTest::GTest GTest::Main packet)
gtest_discover_tests(check_packet_accessors)

# Create an executable for the tests
add_executable(check_packet_alt_payload check_packet_alt_payload.cpp)
target_link_libraries(check_packet_alt_payload PRIVATE GTest::GTest GTest::Main packet)
gtest_discover_tests(check_packet_alt_payload)


# Create an executable for the tests
add_executable(check_packet_create check_packet_create.cpp)
target_link_libraries(check_packet_create PRIVATE GTest::GTest GTest::Main packet)
gtest_discover_tests(check_packet_create)

# Create an executable for the tests
add_executable(check_packet_decode check_packet_decode.cpp)
target_link_libraries(check_packet_decode PRIVATE GTest::GTest GTest::Main packet)
gtest_discover_tests(check_packet_decode)

# Set the working directory for the tests
set_target_properties(
    check_packet_accessors
    check_packet_alt_payload
    check_packet_create
    check_packet_decode
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/bin"
)

# Optionally, you can enable CTest integration to run the tests with 'make test'
enable_testing()
