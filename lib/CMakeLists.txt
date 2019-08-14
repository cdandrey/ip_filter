#lib ipf

cmake_minimum_required(VERSION 3.2)

set (HEADERS ip_filter.h)
set (SOURCES ip_filter.cpp)

if (DEFINED ENV{TRAVIS_BUILD_NUMBER})
    project(prj_libipf VERSION 0.0.$ENV{TRAVIS_BUILD_NUMBER})
else()
    project(prj_libipf VERSION 0.0.1)
endif()

add_library(libipf STATIC ${SOURCES} ${HEADERS})

set_target_properties(
    libipf
    PROPERTIES
    CXX_STANDARD 14
    CXX_STANDARD_REQUIRED ON
)

if (MSVC)
    target_compile_options(
        libipf
        PRIVATE
        /W4
    )
else()
    target_compile_options(
        libipf
        PRIVATE
        -Wall -Wextra -pedantic -Werror
    )
endif()
