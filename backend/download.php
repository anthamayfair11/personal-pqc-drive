<?php
declare(strict_types=1);

/**
 * GET /backend/download.php?id={id}
 *
 * 指定された ID に紐づく暗号化済み .ppqd バイナリを返す。
 * 内容は復号せず、そのまま Content-Type: application/octet-stream で配信する
 * (ゼロ知識: サーバーは中身を一切扱わない)。
 *
 * 失敗時は JSON エラー。成功時はバイナリレスポンス。
 */

/**
 * JSON エラーを返して終了。
 * ヘッダ未送信時のみ Content-Type をセットする (バイナリ送信開始後に来ないようにする)。
 */
function send_json_error(int $http, string $code, string $message): void {
    http_response_code($http);
    if (!headers_sent()) {
        header('Content-Type: application/json; charset=utf-8');
        header('X-Content-Type-Options: nosniff');
    }
    echo json_encode(
        ['error' => $code, 'message' => $message],
        JSON_UNESCAPED_UNICODE
    );
    exit;
}

// 設定読み込み
$config_path = __DIR__ . '/config.php';
if (!file_exists($config_path)) {
    $config_path = __DIR__ . '/config.example.php';
}
/** @var array{storage_dir: string} $config */
$config = require $config_path;

// フォールバック削除: アクセスのたびに期限切れ・孤児ファイルを掃除 (ベストエフォート)
require_once __DIR__ . '/sweep.php';
sweep_expired_files($config['storage_dir']);

// ID の取得と厳格な形式チェック (パストラバーサル対策)
$id = $_GET['id'] ?? '';
if (!is_string($id) || $id === '') {
    send_json_error(400, 'INVALID_FILE', 'id パラメータがありません');
}
// 英数字 + - _ のみを許可 (config.example.php の id_length とアルファベットに合わせる)
if (!preg_match('/^[A-Za-z0-9_\-]{1,64}$/', $id)) {
    send_json_error(400, 'INVALID_FILE', 'id の形式が不正です');
}

$storage_dir = $config['storage_dir'];
$file_path   = $storage_dir . '/' . $id . '.ppqd';
$meta_path   = $storage_dir . '/' . $id . '.meta.json';

// 二重防御: basename と一致するか確認 (preg_match で防いでいるが念のため)
if (basename($file_path) !== $id . '.ppqd') {
    send_json_error(400, 'INVALID_FILE', 'id の形式が不正です');
}

if (!file_exists($file_path) || !file_exists($meta_path)) {
    send_json_error(404, 'NOT_FOUND', '指定された ID のファイルが見つかりません');
}

$meta_raw = file_get_contents($meta_path);
if ($meta_raw === false) {
    send_json_error(500, 'INTERNAL_ERROR', 'メタデータを読み取れません');
}
$meta = json_decode($meta_raw, true);
if (!is_array($meta) || !isset($meta['expireAt'])) {
    send_json_error(500, 'INTERNAL_ERROR', 'メタデータが壊れています');
}

// 有効期限チェック
$expire_at = strtotime((string)$meta['expireAt']);
if ($expire_at === false || $expire_at < time()) {
    send_json_error(410, 'EXPIRED', '有効期限が切れています');
}

// downloadCount のインクリメント (ベストエフォート、失敗しても配信は続ける)
$meta['downloadCount'] = ((int)($meta['downloadCount'] ?? 0)) + 1;
@file_put_contents(
    $meta_path,
    json_encode($meta, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
);

// バイナリ配信
$size = filesize($file_path);
if ($size === false) {
    send_json_error(500, 'INTERNAL_ERROR', 'ファイルサイズが取得できません');
}

header('Content-Type: application/octet-stream');
header('Content-Length: ' . (string)$size);
// .ppqd 拡張子で保存させる (元ファイル名は中身のメタデータブロックに格納されている)
header('Content-Disposition: attachment; filename="' . $id . '.ppqd"');
header('X-Content-Type-Options: nosniff');
// 一時保管なのでキャッシュを禁止
header('Cache-Control: no-store');
header('Pragma: no-cache');

// 既存の出力バッファをクリアしてからファイル送出 (バイナリ整合性のため)
while (ob_get_level() > 0) {
    ob_end_clean();
}
readfile($file_path);
exit;
