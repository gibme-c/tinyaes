add_executable(tinyaes_benchmarks
    bench_all.cpp
)

target_link_libraries(tinyaes_benchmarks PRIVATE tinyaes)
target_include_directories(tinyaes_benchmarks PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
)
set_target_properties(tinyaes_benchmarks PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(tinyaes_benchmarks PRIVATE -Wall -Wextra -Wpedantic)
elseif(MSVC)
    target_compile_options(tinyaes_benchmarks PRIVATE /W4)
endif()
