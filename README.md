# AES_CPP

C++のAESライブラリ専用リポジトリです。ソフトウェア実装とAES-NI実装、ライブラリのテスト・サンプル・Visual Studioプロジェクトを管理します。File E.D.アプリは隣の独立した`file_ed`リポジトリへ分離しました。

```text
AES_CPP/
  libs/aes/       ソース・ヘッダー・テスト・サンプル・Visual Studioプロジェクト
  out/build/      ビルド生成物（Git管理外）
  docs/           構成変更の記録
```

## ビルド

OpenSSL・JSON・YubiKeyは不要です。以下をこのリポジトリのルートで実行します。

```powershell
cmake -S . -B out/build/aes-windows -G "Visual Studio 18 2026" -A x64
cmake --build out/build/aes-windows --config Release --parallel
ctest --test-dir out/build/aes-windows -C Release --output-on-failure
```

Visual Studio 2022ではgeneratorを`Visual Studio 17 2022`に変更します。

Linux:

```bash
cmake -S . -B out/build/aes-linux -DCMAKE_BUILD_TYPE=Release
cmake --build out/build/aes-linux --parallel
ctest --test-dir out/build/aes-linux --output-on-failure
```

Visual Studioソリューションは`libs/aes/AES_CPP.sln`です。[API・使用例](libs/aes/README.md)を参照してください。

## 別プロジェクトから使う

```bash
git submodule add https://github.com/WARUISAME/AES_CPP.git external/AES_CPP
git submodule update --init --recursive
```

```cmake
add_subdirectory(external/AES_CPP)
target_link_libraries(your_app PRIVATE aes-cpp)
```

File E.D.もこの方式でAES_CPPのコミットを固定してビルドします。アプリのビルド・配布・操作説明は`file_ed`リポジトリで管理します。このリポジトリにはアプリのビルドオプションやOpenSSL依存を追加しません。

本ライブラリは教育用途の実装です。
