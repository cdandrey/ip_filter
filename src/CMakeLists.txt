#src 

cmake_minimum_required(VERSION 3.2)

set (SOURCES main.cpp)

if (DEFINED ENV{TRAVIS_BUILD_NUMBER})
    project(prj_ip_filter VERSION 0.0.$ENV{TRAVIS_BUILD_NUMBER})
else()
    project(prj_ip_filter VERSION 0.0.1)
endif()

add_executable(ip_filter ${SOURCES})

set_target_properties(
    ip_filter
    PROPERTIES
    CXX_STANDARD 14
    CXX_STANDARD_REQUIRED ON
)

target_include_directories(
    ip_filter
    PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib
)

target_link_libraries(ip_filter libipf)

if (MSVC)

    target_compile_options(
        ip_filter
        PRIVATE
        /W4
    )

else()

    target_compile_options(
        ip_filter
        PRIVATE
        -Wall -Wextra -pedantic -Werror
    )

endif()

install(TARGETS ip_filter RUNTIME DESTINATION bin)



