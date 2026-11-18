# aes-cpp Library

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/WARUISAME/aes-cpp)

> [!WARNING]
> このライブラリのセキュリティを保証するものではありません。セキュリティが重要な用途には、信頼性の高いライブラリを使用することを強く推奨します。特に、セキュリティクリティカルなアプリケーションでは、例えば[OpenSSL](https://www.openssl.org/)のような広く使用されているライブラリを利用してください。このライブラリは教育目的で提供されており、実際のプロダクション環境での使用は推奨されません。

C++で実装されたAES暗号化ライブラリです。ソフトウェアベースの実装と、パフォーマンスを向上させるAES-NI（Advanced Encryption Standard New Instructions）の両方をサポートしています。

```text
aes-cpp/
  include/AES/
  src/
  examples/
  tests/
  aes-cpp.sln
```

## 主な機能

- **AES暗号化/復号**: AESアルゴリズムに基づいたデータの暗号化と復号。
- **複数の鍵長に対応**: 128ビット、192ビット、256ビットの鍵長をサポート。
- **暗号化モード**:
  - **ECB (Electronic Codebook)**: シンプルな暗号化モード。
  - **CBC (Cipher Block Chaining)**: IV（初期化ベクトル）を使用し、より安全性の高い暗号化を実現。
  - **CBM (Galois/Counter Mode)**: 認証付き暗号化で、暗号化と認証を同時に提供。
- **AES-NI対応**: 対応するCPUでは、ハードウェアアクセラレーションを利用して高速な暗号化/復号処理が可能。
- **クロスプラットフォーム**: CMakeを使用しているため、Windows、Linuxなど、さまざまなプラットフォームでビルドして使用できます。

## 使用方法

CBCモードで暗号化する際、IV（初期化ベクトル）はライブラリ内部で安全な乱数を用いて自動的に生成されます。生成されたIVは、暗号文の先頭16バイトに付加されます。復号時には、ライブラリが自動的に先頭16バイトをIVとして解釈し、残りのデータを復号します。

このライブラリは、平文のパディングにPKCS#7方式を自動的に採用します。暗号化時に適切なパディングが付加され、復号時に自動的に除去されるため、ユーザーが長さを意識する必要はありません。

### インクルード
`#include "AES.h"`
### 基本的な使い方

#### ソフトウェア実装
``` cpp
#include "AES.h"
#include <iostream>
#include <vector>
#include <string>

int main() {
    // 256ビットの鍵
    std::vector<uint8_t> key(32, 0x77);
    std::string plaintext = "これはテストメッセージです。";

    // AESオブジェクトの作成（AES-NIを無効化）
    AES aes(key, false);

    // CBCモードで暗号化
    std::vector<uint8_t> plaintext_bytes(plaintext.begin(), plaintext.end());
    auto ciphertext = aes.encrypt_cbc(plaintext_bytes);

    // CBCモードで復号
    auto decrypted_bytes = aes.decrypt_cbc(ciphertext);
    std::string recovered_text(decrypted_bytes.begin(), decrypted_bytes.end());

    std::cout << "Original:  " << plaintext << std::endl;
    std::cout << "Recovered: " << recovered_text << std::endl;

    return 0;
}
```
#### AES-NI実装

AES-NIを有効にするには、`AES`クラスのコンストラクタで第2引数に`true`を渡します。（第2引数はデフォルトで`true`が設定されているため省略可能です）

```cpp
// AESオブジェクトの作成（AES-NIを有効化）
AES aes_ni(key, true);
// AES aes_ni(key);

// 暗号化・復号の使い方はソフトウェア実装と同じ
auto ciphertext_ni = aes_ni.encrypt_cbc(plaintext_bytes);
auto decrypted_bytes_ni = aes_ni.decrypt_cbc(ciphertext_ni);
```

**AES-NIの利点:**
- **高速処理**: CPUのハードウェア支援により大幅な性能向上
- **セキュリティ**: ハードウェアレベルでの実装によりサイドチャネル攻撃への耐性が向上
- **自動判定**: 実行時にCPUのAES-NI対応を自動判定し、対応していない場合はソフトウェア実装に自動切り替え

**対応CPU:**
- Intel: 2010年以降のWestmere世代以降のプロセッサ
- AMD: 2012年以降のBulldozer世代以降のプロセッサ

**注意:**
AES-NIフラグを`true`に設定していても、CPUがAES-NIに対応していない場合は自動的にソフトウェア実装にフォールバックされます。

## ビルド

以下をこのリポジトリのルートで実行します。

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

Visual Studio では、ルートの `aes-cpp.sln` を開いてビルドできます。

サンプルのビルドだけを行う場合は、構成済みのビルドディレクトリを指定して `example` ターゲットをビルドします。

```powershell
cmake --build out/build/aes-windows --config Release --target example
```

## 別プロジェクトから使う

```bash
git submodule add https://github.com/WARUISAME/aes-cpp.git external/AES_CPP
git submodule update --init --recursive
```

```cmake
add_subdirectory(external/AES_CPP)
target_link_libraries(your_app PRIVATE aes-cpp)
```

## ライセンス

このプロジェクトはMITライセンスの下で公開されています。詳細は[LICENSE](LICENSE)ファイルをご覧ください。
