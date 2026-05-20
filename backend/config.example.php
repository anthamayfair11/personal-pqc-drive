<?php
/**
 * Personal PQC Drive - backend 設定テンプレート
 *
 * 使い方:
 *   cp config.example.php config.php
 *   # config.php を環境に合わせて編集する
 *
 * config.php は .gitignore で除外されているので本番固有の値を入れて問題ない。
 * upload.php / download.php は config.php が存在しなければこの example を読み込む
 * フォールバックを持つので、デフォルト値のままでも動作する。
 */

return [
    // 暗号化済みバイナリの保管ディレクトリ (絶対パス)
    // backend/ から相対で ../storage/ (プロジェクトルート直下)
    'storage_dir' => __DIR__ . '/../storage',

    // 1 ファイルあたりの最大サイズ (bytes)
    // ※ PHP の upload_max_filesize / post_max_size を別途調整する必要がある
    //   (backend/.htaccess および .user.ini 参照)
    'max_file_size' => 100 * 1024 * 1024,  // 100 MB

    // デフォルト有効期限 (秒)。設計方針に合わせて 24 時間
    'default_ttl_seconds' => 24 * 60 * 60,

    // storage/ 配下の合計サイズ上限 (bytes)。これを超えるアップロードは 507 で拒否
    'max_total_storage' => 1024 * 1024 * 1024,  // 1 GB

    // 発行する ID の文字数 (URL-safe な英数字 + ハイフン + アンダースコア)
    // 64 進 × 16 文字 ≒ 96 bit の推測不能性
    'id_length' => 16,
];
