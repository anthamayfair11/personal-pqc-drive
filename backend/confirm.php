<?php
declare(strict_types=1);

/**
 * POST /backend/confirm.php
 * Content-Type: application/json
 * Body: { "id": "abc123..." }
 *
 * 受領確認 (ダウンロード時削除のプライマリ機構)。
 * 指定 ID の .ppqd と .meta.json を削除する。
 *
 * 冪等: 既に削除済みでも 200 { "status": "ok" } を返す。
 * 認証なし: id 自体が秘密の識別子として機能する。
 */

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

function send_error(int $http, string $code, string $message): void {
    http_response_code($http);
    echo json_encode(['error' => $code, 'message' => $message], JSON_UNESCAPED_UNICODE);
    exit;
}

// 設定読み込み (config.php → 無ければ example をフォールバック)
$config_path = __DIR__ . '/config.php';
if (!file_exists($config_path)) {
    $config_path = __DIR__ . '/config.example.php';
}
/** @var array{storage_dir: string} $config */
$config = require $config_path;

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    send_error(405, 'METHOD_NOT_ALLOWED', 'POST のみ受け付けます');
}

// リクエストボディ (JSON) から id を取得
$raw = file_get_contents('php://input');
if ($raw === false || $raw === '') {
    send_error(400, 'INVALID_ID', 'リクエストボディが空です');
}
$body = json_decode($raw, true);
if (!is_array($body) || !isset($body['id']) || !is_string($body['id'])) {
    send_error(400, 'INVALID_ID', 'id が指定されていません');
}
$id = $body['id'];

// バリデーション (download.php と同じルール: パストラバーサル対策)
if (!preg_match('/^[A-Za-z0-9_\-]{1,64}$/', $id)) {
    send_error(400, 'INVALID_ID', 'id の形式が不正です');
}

$storage_dir = $config['storage_dir'];
$file_path   = $storage_dir . '/' . $id . '.ppqd';
$meta_path   = $storage_dir . '/' . $id . '.meta.json';

// 二重防御
if (basename($file_path) !== $id . '.ppqd') {
    send_error(400, 'INVALID_ID', 'id の形式が不正です');
}

// 削除 (冪等: 存在しなくてもエラーにしない)
$deleted_any = false;
foreach ([$file_path, $meta_path] as $path) {
    if (file_exists($path)) {
        if (@unlink($path)) {
            $deleted_any = true;
        } else {
            send_error(500, 'INTERNAL_ERROR', 'ファイル削除に失敗しました');
        }
    }
}

if ($deleted_any) {
    error_log('[confirm] deleted: ' . $id);
}

echo json_encode(['status' => 'ok'], JSON_UNESCAPED_SLASHES);
