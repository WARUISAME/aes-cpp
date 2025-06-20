# AES_CPP Library

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> [!WARNING]
> このライブラリのセキュリティを保証するものではありません。セキュリティが重要な用途には、信頼性の高いライブラリを使用することを強く推奨します。特に、セキュリティクリティカルなアプリケーションでは、例えば[OpenSSL](https://www.openssl.org/)のような広く使用されているライブラリを利用してください。このライブラリは教育目的で提供されており、実際のプロダクション環境での使用は推奨されません。

C++で実装されたAES暗号化ライブラリです。ソフトウェアベースの実装と、パフォーマンスを向上させるAES-NI（Advanced Encryption Standard New Instructions）の両方をサポートしています。

## 主な機能

- **AES暗号化/復号**: AESアルゴリズムに基づいたデータの暗号化と復号。
- **複数の鍵長に対応**: 128ビット、192ビット、256ビットの鍵長をサポート。
- **暗号化モード**:
  - **ECB (Electronic Codebook)**: シンプルな暗号化モード。
  - **CBC (Cipher Block Chaining)**: IV（初期化ベクトル）を使用し、より安全性の高い暗号化を実現。
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

AES-NIを有効にするには、`AES`クラスのコンストラクタで第2引数に`true`を渡します。
``` cpp
// AESオブジェクトの作成（AES-NIを有効化）
AES aes_ni(key, true);

// 暗号化・復号の使い方はソフトウェア実装と同じ
auto ciphertext_ni = aes_ni.encrypt_cbc(plaintext_bytes);
auto decrypted_bytes_ni = aes_ni.decrypt_cbc(ciphertext_ni);
```
## ビルド方法

このプロジェクトはMSVCとCMakeを使用しています。以下の手順でビルドできます。

- **Visual Studio**
 のプロジェクトに直接ライブラリを組み込む場合は、AES.h や AES.cpp などのソースファイルをプロジェクトに追加し、インクルードパスを設定してください。

- CMakeを使用してビルドする場合は、以下の手順に従ってください。
1. **リポジトリをクローン** ``` git clone https://github.com/WARUISAME/AES_CPP.git ```
   ``` cd AES_CPP ```
2. **ビルドディレクトリを作成** ``` mkdir build ```
   ``` cd build ```
3. **CMakeを実行してビルドファイルを生成** ``` cmake .. ```
4. **ビルド** ``` make ```
サンプルプログラムを起動する場合はcmakeのオプションに`-DSAMPLE=ON`を追加してください。

CMakeを使用してビルドする際は、親のMakeFileに以下を追加してください。
``` cmake
add_subdirectory(AES_CPP)
target_link_libraries(your_target_name PRIVATE AES_Library)
```

## ライセンス

このプロジェクトはMITライセンスの下で公開されています。詳細は[LICENSE](LICENSE)ファイルをご覧ください。