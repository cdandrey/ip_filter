cmake_minimum_required(VERSION 3.2)

if (DEFINED ENV{TRAVIS_BUILD_NUMBER})
    project(prj_ip_filter VERSION 0.0.$ENV{TRAVIS_BUILD_NUMBER})
else()
    project(prj_ip_filter VERSION 0.0.1)
endif()

add_executable(ip_filter ip_filter.cpp)

set_target_properties(
    ip_filter
    PROPERTIES
    CXX_STANDARD 14
    CXX_STANDART_REQUIRED ON
)

target_compile_options(
    ip_filter
    PRIVATE
    /W4
)

set(CPACK_GENERATOR DEB)

set(CPACK_PACKAGE_VERSION_MAJOR "${PROJECT_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${PROJECT_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH "${PROJECT_VERSION_PATCH}")

set(CPACK_PACKAGE_CONTACT cdandrey@gmail.com)

install(TARGETS ip_filter RUNTIME DESTINATION bin)

include(CPack)