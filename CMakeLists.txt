# CMakeのバージョンを設定
cmake_minimum_required(VERSION 3.20)
project(AES_CPP)

# ライブラリのソースファイル
set(AES_SOURCES
    src/AES.cpp
    src/GFPoly.cpp
    src/Sbox.cpp
)

# 静的ライブラリとしてAES_Libraryを定義
# 
add_library(AES_Library STATIC ${AES_SOURCES})

# インクルードディレクトリを追加
target_include_directories(AES_Library PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include/AES
)

# コンパイルオプション
target_compile_options(AES_Library PRIVATE -Wno-ignored-attributes)
target_compile_definitions(AES_Library PRIVATE
    $<$<CONFIG:Debug>:_DEBUG>
)

# サンプルをビルドするためのオプション (デフォルトでON)
option(BUILD_EXAMPLES "Build the example executable" OFF)
if(BUILD_EXAMPLES)
    add_executable(example examples/Main.cpp)
    target_link_libraries(example PRIVATE AES_Library)
endif()
