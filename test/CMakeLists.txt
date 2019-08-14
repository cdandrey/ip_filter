
#test

cmake_minimum_required(VERSION 3.2)

set (SOURCES test_ip_filter.cpp)

if (DEFINED ENV{TRAVIS_BUILD_NUMBER})
    project(test_ip_filter VERSION 0.0.$ENV{TRAVIS_BUILD_NUMBER})
else()
    project(test_ip_filter VERSION 0.0.1)
endif()

add_executable(test_ip_filter ${SOURCES})

target_link_libraries(
    test_ip_filter
    PUBLIC
    gtest_main
    libipf
)

if (MSVC)
    target_compile_options(
        test_ip_filter
        PRIVATE
        /W4
    )
else ()
    target_compile_options(
        test_ip_filter
        PRIVATE
        -Wall -Wextra -pedantic -Werror
    )
endif()

add_test(
    NAME test_ip_filter
    COMMAND test_ip_filter
)