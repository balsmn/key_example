cmake_minimum_required(VERSION 3.22)

project(KeyExample VERSION 0.1)

find_package(OpenSSL REQUIRED)

foreach(_target
  key_reader p12_tester)
  add_executable(${_target}
    "${_target}.cc")
  target_include_directories(${_target} PUBLIC
                             "${PROJECT_BINARY_DIR}"
                             )
endforeach()

target_link_libraries(key_reader OpenSSL::SSL)
target_link_libraries(p12_tester OpenSSL::SSL)