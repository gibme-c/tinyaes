if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    return()
endif()
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    return()
endif()

set(FUZZ_TARGETS fuzz_ecb fuzz_cbc fuzz_ctr fuzz_gcm)

foreach(target ${FUZZ_TARGETS})
    add_executable(${target} ${target}.cpp)
    target_link_libraries(${target} PRIVATE tinyaes)
    target_include_directories(${target} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../src
    )
    set_target_properties(${target} PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/fuzz
    )
    target_compile_options(${target} PRIVATE -fsanitize=fuzzer,address)
    set_property(TARGET ${target} APPEND_STRING PROPERTY LINK_FLAGS " -fsanitize=fuzzer,address")
endforeach()
