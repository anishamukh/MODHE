cmake_minimum_required(VERSION 3.10)
project(openfhe-dpad)

# Include directories for OpenFHE
set(OPENFHE_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../MODHE/openfhe-development/src/core/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../MODHE/openfhe-development/src/pke/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../MODHE/openfhe-development/src/binfhe/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../MODHE/openfhe-development/third-party/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../MODHE/openfhe-development/third-party/cereal/include
    ${CMAKE_CURRENT_BINARY_DIR}/openfhe-build/src/core
)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../MODHE/openfhe-development openfhe-build)

# Automatically find all .cpp files in the subdirectories
file(GLOB CPP_FILES "benchmarks/*.cpp")

# Create an executable for every .cpp file found, and link src/DPadHE.cpp to it
foreach(CPP_FILE ${CPP_FILES})
    get_filename_component(TARGET_NAME ${CPP_FILE} NAME_WE)
    add_executable(${TARGET_NAME} ${CPP_FILE} src/DPadHE.cpp)
    target_include_directories(${TARGET_NAME} PRIVATE ${OPENFHE_INCLUDE_DIRS})
    target_link_libraries(${TARGET_NAME} OPENFHEpke OPENFHEcore OPENFHEbinfhe)
endforeach()
