<?php
declare(strict_types=1);

/**
 * POST /backend/upload.php
 *
 * multipart/form-data の "file" フィールドに暗号化済み .ppqd バイナリを乗せて
 * 送信する。サーバーは内容を一切検査せず、ランダム ID で保管する (ゼロ知識性)。
 *
 * 成功時レスポンス:
 *   { "id": "...", "expireAt": "ISO8601", "downloadUrl": "download.php?id=..." }
 *
 * エラー時レスポンス (HTTP ステータス + JSON):
 *   { "error": "ERROR_CODE", "message": "ユーザー向けメッセージ" }
 */

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

/**
 * エラーレスポンスを返して終了する (never 戻り値)。
 */
function send_error(int $http, string $code, string $message): void {
    http_response_code($http);
    echo json_encode(
        ['error' => $code, 'message' => $message],
        JSON_UNESCAPED_UNICODE
    );
    exit;
}

// 設定読み込み (config.php → 無ければ example をフォールバック)
$config_path = __DIR__ . '/config.php';
if (!file_exists($config_path)) {
    $config_path = __DIR__ . '/config.example.php';
}
/** @var array{
 *   storage_dir: string,
 *   max_file_size: int,
 *   default_ttl_seconds: int,
 *   max_total_storage: int,
 *   id_length: int
 * } $config */
$config = require $config_path;

// フォールバック削除: アクセスのたびに期限切れ・孤児ファイルを掃除 (ベストエフォート)
require_once __DIR__ . '/sweep.php';
sweep_expired_files($config['storage_dir']);

// メソッドチェック
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    send_error(405, 'METHOD_NOT_ALLOWED', 'POST のみ受け付けます');
}

// アップロードファイル存在チェック
if (!isset($_FILES['file'])) {
    // post_max_size を超えると $_FILES が空になる (PHP 仕様)
    if (
        (int)($_SERVER['CONTENT_LENGTH'] ?? 0) > 0
        && empty($_POST) && empty($_FILES)
    ) {
        send_error(413, 'FILE_TOO_LARGE', 'リクエスト全体のサイズが上限を超えています');
    }
    send_error(400, 'INVALID_FILE', 'file フィールドが見つかりません');
}

$upload_err = (int)$_FILES['file']['error'];
if ($upload_err !== UPLOAD_ERR_OK) {
    if ($upload_err === UPLOAD_ERR_INI_SIZE || $upload_err === UPLOAD_ERR_FORM_SIZE) {
        send_error(413, 'FILE_TOO_LARGE', 'ファイルサイズが PHP の上限を超えています');
    }
    if ($upload_err === UPLOAD_ERR_NO_FILE) {
        send_error(400, 'INVALID_FILE', 'ファイルがアップロードされていません');
    }
    send_error(400, 'INVALID_FILE', 'アップロードに失敗しました (error code ' . $upload_err . ')');
}

$tmp_path  = (string)$_FILES['file']['tmp_name'];
$file_size = (int)$_FILES['file']['size'];

// アプリ側の上限チェック (PHP ini を超えていても念のため)
if ($file_size > $config['max_file_size']) {
    send_error(
        413,
        'FILE_TOO_LARGE',
        sprintf(
            'ファイルサイズ %d bytes が上限 %d bytes を超えています',
            $file_size,
            $config['max_file_size']
        )
    );
}
if ($file_size === 0) {
    send_error(400, 'INVALID_FILE', '空ファイルは受け付けません');
}

// HTTP 経由でアップロードされたファイルかチェック (パストラバーサル等の防御)
if (!is_uploaded_file($tmp_path)) {
    send_error(400, 'INVALID_FILE', 'アップロードファイルが不正です');
}

// storage ディレクトリの準備
$storage_dir = $config['storage_dir'];
if (!is_dir($storage_dir)) {
    if (!mkdir($storage_dir, 0755, true) && !is_dir($storage_dir)) {
        send_error(500, 'INTERNAL_ERROR', '保管ディレクトリを作成できません');
    }
}

// 合計ストレージ使用量チェック
$total_used = 0;
foreach (glob($storage_dir . '/*.ppqd') ?: [] as $existing) {
    $total_used += (int)(filesize($existing) ?: 0);
}
if ($total_used + $file_size > $config['max_total_storage']) {
    send_error(
        507,
        'STORAGE_FULL',
        'サーバー側のストレージ容量が一時的に不足しています'
    );
}

/**
 * URL-safe な ID を生成する。
 * 文字集合 64 種 (英数字 + - _) × $length 文字。
 * 16 文字なら 64^16 = 2^96 通り、衝突確率は実用上ゼロ。
 */
function generate_id(int $length): string {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    $alphabet_len = strlen($alphabet);
    // 偏りを避けるため、必要量より多めに引いて剰余を取る (簡易な rejection)
    $bytes = random_bytes($length);
    $out = '';
    for ($i = 0; $i < $length; $i++) {
        $out .= $alphabet[ord($bytes[$i]) % $alphabet_len];
    }
    return $out;
}

// ID の衝突を回避 (確率的にはまず起きないが念のため)
$id = null;
for ($attempt = 0; $attempt < 5; $attempt++) {
    $candidate = generate_id((int)$config['id_length']);
    if (!file_exists($storage_dir . '/' . $candidate . '.ppqd')) {
        $id = $candidate;
        break;
    }
}
if ($id === null) {
    send_error(500, 'INTERNAL_ERROR', 'ID 生成に失敗しました');
}

// 保存
$file_path = $storage_dir . '/' . $id . '.ppqd';
$meta_path = $storage_dir . '/' . $id . '.meta.json';

if (!move_uploaded_file($tmp_path, $file_path)) {
    send_error(500, 'INTERNAL_ERROR', 'ファイル保存に失敗しました');
}
@chmod($file_path, 0644);

$now       = time();
$expire_at = $now + (int)$config['default_ttl_seconds'];
$meta = [
    'id'            => $id,
    'uploadedAt'    => date('c', $now),
    'expireAt'      => date('c', $expire_at),
    'size'          => $file_size,
    'downloadCount' => 0,
    'maxDownloads'  => null,
];
$meta_json = json_encode($meta, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
if ($meta_json === false || file_put_contents($meta_path, $meta_json) === false) {
    @unlink($file_path);
    send_error(500, 'INTERNAL_ERROR', 'メタデータ保存に失敗しました');
}
@chmod($meta_path, 0644);

// 成功レスポンス
echo json_encode([
    'id'          => $id,
    'expireAt'    => date('c', $expire_at),
    'downloadUrl' => 'download.php?id=' . urlencode($id),
], JSON_UNESCAPED_SLASHES);
