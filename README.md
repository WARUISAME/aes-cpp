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

このプロジェクトはCMakeを使用しています。以下の手順でビルドできます。

1. **リポジトリをクローン**git clone <repository-url>
   cd AES_CPP
2. **ビルドディレクトリを作成**mkdir build
   cd build
3. **CMakeを実行してビルドファイルを生成**cmake ..
4. **ビルド**
   - **Windows (Visual Studio)** ```bash
 cmake --build . --config Release
 ```   - **Linux/macOS** ```bash
     make ```

CMakeを使用してビルドする際は、親のMakeFileに以下を追加してください。
``` cmake
add_subdirectory(AES_CPP)
target_link_libraries(your_target_name PRIVATE AES_Library)
```
MSVCを利用する場合は、プロジェクトにインクルードを直接を追加する必要があります。
## ライセンス

このプロジェクトはMITライセンスの下で公開されています。詳細は[LICENSE](LICENSE)ファイルをご覧ください。

## 貢献

バグ報告や機能改善のプルリクエストを歓迎します。貢献を検討される方は、まずIssueを作成して議論を始めてください。