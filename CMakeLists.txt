
#root

cmake_minimum_required(VERSION 3.2)

if (DEFINED ENV{TRAVIS_BUILD_NUMBER})
    project(prj_ip_filter VERSION 0.0.$ENV{TRAVIS_BUILD_NUMBER})
else()
    project(prj_ip_filter VERSION 0.0.1)
endif()

add_subdirectory(src)
add_subdirectory(lib)
add_subdirectory(test)

set(CPACK_GENERATOR DEB)

set(CPACK_PACKAGE_VERSION_MAJOR "${PROJECT_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${PROJECT_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH "${PROJECT_VERSION_PATCH}")

set(CPACK_PACKAGE_CONTACT cdandrey@gmail.com)

include(CPack)
