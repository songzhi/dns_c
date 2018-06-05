cmake_minimum_required(VERSION 3.0.0)
project(dns VERSION 0.1.0)
add_executable(dns DataStructure.c )

SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)