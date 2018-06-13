cmake_minimum_required(VERSION 3.0.0)
project(dns VERSION 0.1.0)
add_executable(client client.c DNSPacket.c )
add_executable(server server.c DNSPacket.c )
add_executable(root root.c DNSPacket.c )
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include_directories(
		/usr/include/glib-2.0
		/usr/lib/x86_64-linux-gnu/glib-2.0/include
)
target_link_libraries(root glib-2.0)
include(CPack)