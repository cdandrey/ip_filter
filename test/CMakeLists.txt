
#test

cmake_minimum_required(VERSION 3.2)

set (THIS test_ip_filter)
set (SOURCES test_ip_filter.cpp)

if (DEFINED ENV{TRAVIS_BUILD_NUMBER})
    message(STATUS TRAVIS_BUILD_NUMBER : $ENV{TRAVIS_BUILD_NUMBER})
    project(${THIS} VERSION 0.0.$ENV{TRAVIS_BUILD_NUMBER})
else()
    project(${THIS} VERSION 0.0.1)
endif()

find_package(GTest REQUIRED)
find_package(Threads REQUIRED)

add_executable(${THIS} ${SOURCES})

include_directories( 
    ${GTES_INCLUDE_DIRS}
)

set_target_properties(
    ${THIS}
    PROPERTIES
    CXX_STANDARD 14
    CXX_STANDARD_REQUIRED ON
)

target_include_directories(
    ${THIS}
    PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib
)

target_link_libraries(${THIS} ${GTEST_BOTH_LIBRARIES}) 
target_link_libraries(${THIS} ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(${THIS} libipf)

if (MSVC)
    target_compile_options(
        ${THIS}
        PRIVATE
        /W4
    )
else ()
    target_compile_options(
        ${THIS}
        PRIVATE
        -Wall -Wextra -pedantic -Werror
    )
endif()

enable_testing()

add_test(${THIS} ${THIS})
