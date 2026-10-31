# AES-CPP プロジェクト開発ガイド

## アーキテクチャ概要

このプロジェクトは教育目的のAES暗号化ライブラリで、**デュアル実装アーキテクチャ**を採用：

- **ソフトウェア実装**: NIST FIPS 197準拠の純粋C++実装
- **AES-NI実装**: Intel/AMD CPUのハードウェア加速を利用（自動フォールバック付き）

### 数学的基盤とコンポーネント

プロジェクトの核心は有限体演算に基づく階層的設計：

```
GFPolynomial (GF(2^8)演算) 
    ↓
GFCPolynomial (4つのGF(2^8)係数多項式)
    ↓
State (AES状態マトリックス4x4)
    ↓
AESクラス (暗号化・復号化ロジック)
```

**重要**: `State`クラスは行列を`s[r + 4*c]`でカラムメジャー順で格納する

## 主要な開発パターン

### デュアル実装パターン
各暗号化操作で条件分岐により実装を選択：
```cpp
if (aesniSupported) {
    // AES-NI __m128i レジスタ操作
    __m128i block = _mm_loadu_si128(...);
    block = _mm_aesenc_si128(block, roundKey);
} else {
    // ソフトウェア State クラス操作
    state = subBytes(state);
    state = shiftRows(state);
}
```

### セキュリティ重視の設計
- **自動メモリクリア**: デストラクタで`secureZeroMemory()`により機密データを消去
- **PKCS#7パディング**: 自動適用・除去
- **IV自動生成**: CBCモードで暗号文先頭16バイトに埋め込み

### GCM実装パターン
GCMモードは複数の専用関数で構成：
- `encryptGCM_ctr()` / `decryptGCM_ctr()`: CTRモード暗号化
- `gfMultiply()`: GF(2^128)での乗算
- `ghash()`: GHASH認証関数
- `generateCounterBlock()`: カウンターブロック生成

## ビルドとテスト

### CMakeワークフロー
```bash
mkdir build && cd build
cmake ..
make                    # 静的ライブラリ
make example           # サンプル実行ファイル
```

### Visual Studioワークフロー
- `libs/aes/AESStaticlib.vcxproj`: 静的ライブラリプロジェクト
- `libs/aes/Project1.vcxproj`: サンプル実行プロジェクト（"AES"にリネーム済み）
- インクルードパス: `include\AES`
- 出力先: `out/build/aes-vs/`

### クロスプラットフォーム考慮事項
- **Windows**: MSVCコンパイラ、Visual Studio統合
- **Linux/GCC**: CMakeでの`-maes -mssse3 -mpclmul`フラグ必須
- **AES-NI検出**: 実行時CPU機能判定により自動切り替え

## コードベース固有の規約

### ファイル構成
- `libs/aes/include/AES/`: 全ヘッダーファイル（モジュラー設計）
- `libs/aes/src/`: 実装ファイル（`AES.cpp`が主要ロジック）
- `libs/aes/examples/Main.cpp`: 両実装の比較テスト

### デバッグパターン
- `#ifdef _DEBUG`: デバッグ情報表示（`paddingPrintHex()`等）
- 16進出力: `std::hex << std::setw(2) << std::setfill('0')`
- 相互運用性テスト: ソフトウェア暗号化→AES-NI復号、逆も確認

### エラーハンドリング
- `std::invalid_argument`: 入力サイズ不正
- `std::runtime_error`: GCM認証失敗
- 例外安全性: RAIIとデストラクタでのリソース管理

## 拡張時の注意点

### 新しい暗号化モード追加
1. `AES.h`でパブリック関数宣言
2. ソフトウェア実装をprivate関数で追加
3. AES-NI版も並行実装（`aesniSupported`で分岐）
4. `libs/aes/examples/Main.cpp`でテストケース追加

### 数学的依存関係
- S-box操作: `GFPolynomial`の逆元計算に依存
- MixColumns: `GFCPolynomial`の多項式乗算に依存
- **重要**: `initInverse()`を暗号化前に呼び出す必要あり

## 実装の互換性保証

このライブラリは**相互運用性**を重視：
- ソフトウェア実装とAES-NI実装の暗号化結果は完全に互換
- 同一鍵・同一IVで同一暗号文を生成
- `libs/aes/examples/Main.cpp`で相互復号テストを実施

新機能追加時はこの互換性を必ず維持すること。

## ワークスペース分離

このリポジトリはAESライブラリ専用です。ソースは`libs/aes`、ビルド生成物は`out/build`へ置きます。File E.D.は独立した`file_ed`リポジトリへ分離し、このリポジトリをGit submoduleとして参照します。アプリのソース・依存関係・配布スクリプトをAES_CPPへ追加しないこと。
