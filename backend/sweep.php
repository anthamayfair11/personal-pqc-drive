<?php
declare(strict_types=1);

/**
 * sweep.php - 期限切れ・孤児ファイルのスイープ (フォールバック削除機構)
 *
 * 自動削除はハイブリッド方式:
 *   - プライマリ: confirm.php (受領確認時に即削除)
 *   - フォールバック: この sweep を upload.php / download.php アクセス時に呼ぶ
 *     → cron 不要で、アクセスがある限り期限切れファイルが掃除される
 *
 * 排他制御: storage_dir/.sweep.lock を flock(LOCK_EX|LOCK_NB) で確保。
 * 取れなければ即 skipped で返す (多重起動防止)。正常終了時に明示解放し、
 * register_shutdown_function を異常終了時の保険として併用する。
 */

/**
 * storage_dir 内の期限切れファイルと孤児ファイルを削除する。
 *
 * @return array{deleted: int, bytes_freed: int, errors: int, skipped: bool}
 */
function sweep_expired_files(string $storage_dir): array {
    $result = ['deleted' => 0, 'bytes_freed' => 0, 'errors' => 0, 'skipped' => false];

    if (!is_dir($storage_dir)) {
        return $result;
    }

    // --- ロック取得 ---
    $lock_path = $storage_dir . '/.sweep.lock';
    $lock_fp = @fopen($lock_path, 'c');
    if ($lock_fp === false) {
        // ロックファイルすら開けない場合はスイープを諦める (ベストエフォート)
        $result['skipped'] = true;
        return $result;
    }
    if (!flock($lock_fp, LOCK_EX | LOCK_NB)) {
        // 他プロセスがスイープ中
        fclose($lock_fp);
        $result['skipped'] = true;
        return $result;
    }

    // 異常終了 (fatal error 等) でもロックが残らないよう保険を掛ける。
    // 正常終了時は関数末尾で明示解放するので、その後この shutdown は
    // is_resource チェックにより no-op になる。
    register_shutdown_function(static function () use ($lock_fp): void {
        if (is_resource($lock_fp)) {
            @flock($lock_fp, LOCK_UN);
            @fclose($lock_fp);
        }
    });

    $now = time();

    // .ppqd と .meta.json をペアで削除するヘルパ
    $delete_pair = static function (string $id) use ($storage_dir, &$result): void {
        foreach ([$id . '.ppqd', $id . '.meta.json'] as $name) {
            $path = $storage_dir . '/' . $name;
            if (!file_exists($path)) {
                continue;
            }
            $size = (int)(filesize($path) ?: 0);
            if (@unlink($path)) {
                $result['bytes_freed'] += $size;
            } else {
                $result['errors']++;
                error_log('[sweep] delete-failed: ' . $id . ' (unlink returned false for ' . $name . ')');
            }
        }
    };

    // (1) meta.json を走査: 期限切れ・壊れ・expireAt 欠落を削除
    foreach (glob($storage_dir . '/*.meta.json') ?: [] as $meta_path) {
        $base = basename($meta_path, '.meta.json');
        $raw = @file_get_contents($meta_path);
        if ($raw === false) {
            error_log('[sweep] corrupt-meta: ' . $base . ' (read failed)');
            $delete_pair($base);
            $result['deleted']++;
            continue;
        }
        $meta = json_decode($raw, true);
        if (!is_array($meta)) {
            error_log('[sweep] corrupt-meta: ' . $base . ' (json decode failed)');
            $delete_pair($base);
            $result['deleted']++;
            continue;
        }
        if (!isset($meta['expireAt'])) {
            error_log('[sweep] corrupt-meta: ' . $base . ' (expireAt missing)');
            $delete_pair($base);
            $result['deleted']++;
            continue;
        }
        $expire = strtotime((string)$meta['expireAt']);
        if ($expire === false || $expire < $now) {
            $ppqd_path = $storage_dir . '/' . $base . '.ppqd';
            $ppqd_size = file_exists($ppqd_path) ? (int)(filesize($ppqd_path) ?: 0) : 0;
            error_log('[sweep] expired: ' . $base . ' (' . $ppqd_size . ' bytes)');
            $delete_pair($base);
            $result['deleted']++;
        }
    }

    // (2) .ppqd を走査: 対応する meta.json が無い孤児を削除
    foreach (glob($storage_dir . '/*.ppqd') ?: [] as $ppqd_path) {
        $base = basename($ppqd_path, '.ppqd');
        if (!file_exists($storage_dir . '/' . $base . '.meta.json')) {
            $size = (int)(filesize($ppqd_path) ?: 0);
            if (@unlink($ppqd_path)) {
                $result['bytes_freed'] += $size;
                $result['deleted']++;
                error_log('[sweep] orphan-ppqd: ' . $base . ' (no corresponding .meta.json)');
            } else {
                $result['errors']++;
                error_log('[sweep] delete-failed: ' . $base . ' (unlink returned false for .ppqd)');
            }
        }
    }

    // (3) meta.json を走査: 対応する .ppqd が無い孤児を削除
    foreach (glob($storage_dir . '/*.meta.json') ?: [] as $meta_path) {
        $base = basename($meta_path, '.meta.json');
        if (!file_exists($storage_dir . '/' . $base . '.ppqd')) {
            $size = (int)(filesize($meta_path) ?: 0);
            if (@unlink($meta_path)) {
                $result['bytes_freed'] += $size;
                $result['deleted']++;
                error_log('[sweep] orphan-meta: ' . $base . ' (no corresponding .ppqd)');
            } else {
                $result['errors']++;
                error_log('[sweep] delete-failed: ' . $base . ' (unlink returned false for .meta.json)');
            }
        }
    }

    // --- 正常終了時の明示解放 (連続呼び出しでロック競合しないように) ---
    @flock($lock_fp, LOCK_UN);
    @fclose($lock_fp);

    return $result;
}
