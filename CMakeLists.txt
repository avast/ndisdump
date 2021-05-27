cmake_minimum_required(VERSION 3.16)

set(NDISDUMP_VERSION "0.0.0" CACHE STRING "ndisdump version number (major.minor.patch)")
project(ndisdump VERSION "${NDISDUMP_VERSION}")

configure_file(src/ndisdump.rc.in ndisdump.rc)

add_executable(ndisdump
	src/main.cpp
	src/cmdline.h
	src/comptr.h
	src/hr.h
	src/pcapng.h
	src/registry.h
	src/sigint.h
	src/utf8.h
	"${CMAKE_CURRENT_BINARY_DIR}/ndisdump.rc"
	)
target_compile_features(ndisdump PUBLIC cxx_std_20)
target_link_libraries(ndisdump PUBLIC iphlpapi.lib)
