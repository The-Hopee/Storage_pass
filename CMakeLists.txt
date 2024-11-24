
cmake_minimum_required(VERSION 3.5)

project(Storage)

add_executable(Storage main.cpp)

# find_path(cppcrypto_INCLUDE_DIR cppcrypto/logging.h)
# message(STATUS "cppcrypto header found at: ${cppcrypto_INCLUDE_DIR}")

# find_library(cppcrypto_LIB glog)
# message(STATUS "libcppcrypto found at: ${cppcrypto_LIB}")

# mark_as_advanced(cppcrypto_INCLUDE_DIR cppcrypto_LIB)

# include(FindPackageHandleStandardArgs)
# find_package_handle_standard_args(cppcrypto REQUIRED_VARS
# cppcrypto_INCLUDE_DIR
# cppcrypto_LIB
# )

# if(cppcrypto_FOUND AND NOT TARGET cppcrypto)
#   add_library(cppcrypto SHARED IMPORTED)
#   set_target_properties(cppcrypto PROPERTIES
#     IMPORTED_LINK_INTERFACE_LANGUAGES "CXX"
#     IMPORTED_LOCATION "${cppcrypto_LIB}"
#     INTERFACE_INCLUDE_DIRECTORIES
#       "${cppcrypto_INCLUDE_DIR}"
#     )
# endif()

# find_package(cppcrypto)

#  find_library(LIBCPPCRYPTO_PATH cppcrypto)
#  message(STATUS "libcppcrypto found at: ${LIBCPPCRYPTO_PATH}")
#  add_library(rtt::libcppcrypto STATIC IMPORTED)
#  set_target_properties(rtt::libcppcrypto 
#  PROPERTIES
#  IMPORTED_LOCATION ${LIBCPPCRYPTO_PATH} 
#  INTERFACE_INCLUDE_DIRECTORIES "/usr/include/cppcrypto"
# )
 
# target_link_libraries(main PRIVATE rtt::libcppcrypto setupapi  -municode wsock32 ws2_32  Iphlpapi iconv ssp )

add_subdirectory(include)
target_link_libraries(Storage PUBLIC sha256)
target_include_directories(Storage PUBLIC "${PROJECT_BINARY_DIR}" "${PROJECT_SOURCE_DIR}/include")

find_library(LIBCRYPTOPP_PATH cryptopp)
add_library(rtt::libcryptopp STATIC IMPORTED)
set_target_properties(rtt::libcryptopp 
 PROPERTIES
 IMPORTED_LOCATION ${LIBCRYPTOPP_PATH} 
 INTERFACE_INCLUDE_DIRECTORIES "/usr/local/include/cryptopp"# где найти библиотеки
)

target_link_libraries(Storage PRIVATE rtt::libcryptopp)