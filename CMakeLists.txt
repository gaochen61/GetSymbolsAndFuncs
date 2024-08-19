cmake_minimum_required(VERSION 3.20)
project(test)

set(CMAKE_CXX_STANDARD_REQUIRED ON)
# specify C++20 version
set(CMAKE_CXX_STANDARD 20)


# set(DynamoRIO_DIR "C:/HomeSpace/BinaryAnalysis/DynamoRIO-Windows-9.0.1/cmake")
set(DynamoRIO_DIR "D:/C++projects/binary_code_analysis/DynamoRIOs_files/DynamoRIO-Windows-10.0.0/DynamoRIO-Windows-10.0.0/cmake")
# set(DrMemoryFramework_DIR "C:/HomeSpace/BinaryAnalysis/DrMemory-Windows-2.5.0/drmf")

find_package(DynamoRIO REQUIRED)
find_package(DrMemoryFramework REQUIRED)

# add_library(taint_engine SHARED "lib/engine.c")
# include_directories(PUBLIC "lib")

add_library(test SHARED yyx_pre_analysis.cpp)
# target_include_directories(yyx_taint PUBLIC "lib")
# target_link_libraries(yyx_taint taint_engine)

configure_DynamoRIO_client(test)
use_DynamoRIO_extension(test drmgr)
use_DynamoRIO_extension(test drreg)
use_DynamoRIO_extension(test drx)
use_DynamoRIO_extension(test drutil)
use_DynamoRIO_extension(test drsyscall)
use_DynamoRIO_extension(test drsyms)
use_DynamoRIO_extension(test drsyms)
use_DynamoRIO_extension(test drwrap)
use_DynamoRIO_extension(test droption) 


