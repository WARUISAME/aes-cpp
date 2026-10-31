# フォルダー整理

旧パスと新パスの対応です。ソース・既存の変更内容は移動して保持しています。

| 旧 | 新 |
|---|---|
| `include/`, `src/`, `examples/`, `tests/` | `libs/aes/`内の同名フォルダー |
| `AES_CPP.sln`, `*.vcxproj`, `*.vcxproj.filters`, 関連ユーザー設定 | `libs/aes/` |
| ライブラリの`README.md` | `libs/aes/README.md` |
| `.deps/` | `out/deps/` |
| `build/`, `build-file-ed*/` | `out/archive/`内の同名フォルダー |
| `AES/`, `AESStaticlib/`, `Release/`, `x64/` | `out/archive/`内の同名フォルダー |

古いCMakeキャッシュは旧ソースパスを持つため保管用です。新しい`out/build`に構成し直してください。今後は配布フォルダー`dist/file-ed-windows`から起動します。

ユーザーごとの設定・公開鍵プロファイル（`%LOCALAPPDATA%/FileED`または`~/.config/file-ed`）は移動しません。実行ファイルと同じ場所へPIN・秘密鍵を保存する変更もありません。

## 独立リポジトリへの分離（2026-10-31）

`AES_CPP`はライブラリ専用とし、File E.D.のソース・テスト・文書・配布スクリプト・CIを同階層の`file_ed`リポジトリへ移動しました。`file_ed/external/AES_CPP`はこのリポジトリを参照するGit submoduleです。旧ビルドキャッシュはソースパスが変わるため保管用とし、分離後のリポジトリで構成し直します。設定・公開鍵プロファイルの保存先は変更しません。
