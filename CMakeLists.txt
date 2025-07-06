# CMakeのバージョンを設定
cmake_minimum_required(VERSION 3.20)
project(aes-cpp)

# ライブラリのソースファイル
set(AES_SOURCES
    src/AES.cpp
    src/GFPoly.cpp
    src/Sbox.cpp
)

# 静的ライブラリとしてAES_Libraryを定義
# 
add_library(aes-cpp STATIC ${AES_SOURCES})

# インクルードディレクトリを追加
target_include_directories(aes-cpp PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include/AES
)

# コンパイルオプション
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(aes-cpp PRIVATE -Wno-ignored-attributes -maes -mssse3 -mpclmul)
elseif(MSVC)
    #target_compile_options(aes-cpp PRIVATE /arch:AES)
endif()

target_compile_definitions(aes-cpp PRIVATE
    $<$<CONFIG:Debug>:_DEBUG>
)

# make example でサンプルをビルドできるカスタムターゲット
add_executable(example_target EXCLUDE_FROM_ALL examples/Main.cpp)
target_link_libraries(example_target PRIVATE aes-cpp)
set_target_properties(example_target PROPERTIES OUTPUT_NAME example)

# make example でビルドできるようにエイリアスを作成
add_custom_target(example DEPENDS example_target)
