# CMakeのバージョンを設定
cmake_minimum_required(VERSION 3.20)

add_library(AES_Library STATIC 
    AES.cpp
    GFPoly.cpp
    Sbox.cpp
)

# インクルードディレクトリを追加
target_include_directories(AES_Library PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR} # AES ディレクトリ (AES.h など)
)