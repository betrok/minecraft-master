<?php
require_once CONFIGDIR . DIRECTORY_SEPARATOR . 'config.php';

function m_login(string $user, string $password): bool
{
    $conn = dbconn();
    $stmt = $conn->prepare('SELECT salt, password FROM players WHERE player = ?');
    $stmt->execute([$user]);
    $result = $stmt->fetch();
    if ($result === false) {
        return false;
    }
    list($salt, $password2) = $result;

    if (salt($salt, $password) !== $password2) {
        return false;
    }

    $accessToken = generate_uuid();
    $stmt = $conn->prepare('UPDATE players SET accessToken = ? WHERE player = ?');
    $stmt->execute([$accessToken, $user]);
    return true;
}

function m_join(string $client_token, string $access_token): bool
{
    $conn = dbconn();
    $stmt = $conn->prepare(
        'SELECT COUNT(*) FROM players WHERE clientToken = ? AND accessToken = ?'
    );
    $stmt->execute([$client_token, $access_token]);
    if ((int) $stmt->fetchColumn() == 0) {
        return false;
    }
    if ($GLOBALS['DEBUG']) {
        error_log("Join OK: {$access_token}");
    }
    return true;
}

function m_isMojang(string $user): bool
{
    $conn = dbconn();
    $stmt = $conn->prepare('SELECT isMojang FROM players WHERE player = ?');
    $stmt->execute([$user]);
    $result = $stmt->fetch();
    if ($result === false) {
        return false;
    }
    return (bool) $result['isMojang'];
}

function mojang_hasJoined(string $user, string $serverId)
{
    $conn = dbconn();
    $stmt = $conn->prepare('SELECT clientToken FROM players WHERE player = ?');
    $stmt->execute([$user]);
    $client_token = $stmt->fetchColumn();
    if ($client_token === false) {
        return false;
    }

    $json = file_get_contents(
        "https://sessionserver.mojang.com/session/minecraft/hasJoined?username={$user}&serverId={$serverId}"
    );
    if (strlen($json) === 0) {
        return false;
    }
    $jsonData = json_decode($json, true);
    $jsonData['id'] = $client_token;
    return json_encode($jsonData);
}

function m_hasJoined(string $user, string $serverId): bool
{
    $conn = dbconn();
    $stmt = $conn->prepare('SELECT serverId FROM players WHERE player = ?');
    $stmt->execute([$user]);
    $serverId2 = $stmt->fetchColumn();
    if ($serverId2 === false) {
        if ($GLOBALS['DEBUG']) {
            error_log("hasJoined: {$user} {$serverId} is not here");
        }
        return false;
    }
    if ($serverId !== $serverId2) {
        if ($GLOBALS['DEBUG']) {
            error_log("hasJoined: {$serverId} {$serverId2} !=");
        }
        return false;
    }
    return true;
}

function m_checkban(string $user)
{
    $conn = dbconn();
    $stmt = $conn->prepare(
        'SELECT reason, who_banned, banned_at FROM banned_players WHERE player = ?'
    );
    if (!$stmt->execute([$user])) {
        return false;
    }
    $result = $stmt->fetch();
    if ($result === false) {
        return false;
    }
    list($reason, $whoBanned, $bannedAt) = $result;
    return [
        'reason'     => $reason,
        'who_banned' => $whoBanned,
        'banned_at'  => $bannedAt,
    ];
}

function m_ban(string $user, string $target, $reason): bool
{
    $conn = dbconn();
    $stmt = $conn->prepare(
        'INSERT INTO banned_players (player, reason, who_banned) VALUES (?, ?, ?)'
    );
    if (!$stmt->execute([$target, $reason, $user])) {
        error_log('m_ban execute error');
        return false;
    }
    return true;
}

function m_unban(string $user, string $target, string $reason): bool
{
    $conn = dbconn();
    $stmt = $conn->prepare('DELETE FROM banned_players WHERE player = ?');
    if (!$stmt->execute([$target])) {
        return false;
    }
    $stmt = $conn->prepare(
        'INSERT INTO unbanned_players (player, reason, who_unbanned) VALUES (?, ?, ?)'
    );
    if (!$stmt->execute([$target, $reason, $user])) {
        return false;
    }
    return true;
}

function m_isMod(string $user): bool
{
    $conn = dbconn();
    $stmt = $conn->prepare('SELECT isMod FROM players WHERE player = ?');
    if (!$stmt->execute([$user])) {
        return false;
    }
    $result = $stmt->fetch();
    if ($result === false) {
        // well, not really a problem
        return false;
    }
    return (bool) $result['isMod'];
}

function echo_log(string $line)
{
    if ($GLOBALS['DEBUG']) {
        error_log($line);
    }
    echo $line;
}

function dbconn(): PDO
{
    static $conn = null;
    if (!is_null($conn)) {
        return $conn;
    }

    $conn = new PDO(
        sprintf(
            '%s:host=%s;dbname=%s;charset=%s',
            $GLOBALS['db_type'],
            $GLOBALS['db_host'],
            $GLOBALS['db_name'],
            $GLOBALS['db_charset']
        ),
        $GLOBALS['db_username'],
        $GLOBALS['db_password'],
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );

    return $conn;
}

function salt(string $salt, string $password): string
{
    return sha1($salt . sha1($password));
}

function generate_uuid(bool $hyphen = true): string
{
    // Mojang UUIDs are variant 1, so this is variant 2
    $chars = [
        bin2hex(random_bytes(4)),
        bin2hex(random_bytes(2)),
        dechex(random_int(0, 0x0fff) | 0x4000),
        dechex(random_int(0, 0x1fff) | 0xC000),
        bin2hex(random_bytes(6)),
    ];
    return implode(($hyphen ? '-' : ''), $chars);
}

function to_uuid(string $str)
{
    $ret = filter_var($str, FILTER_VALIDATE_REGEXP, [
        'options' => ['regexp' => '/^[0-9a-fA-F]+$/'],
    ]);
    if ($ret === false || strlen($ret) !== 32) {
        return null;
    }
    foreach ([8, 13, 18, 23] as $pos) {
        $ret = substr_replace($ret, '-', $pos, 0);
    }
    return strtolower($ret);
}

function set_skin(string $user, string $skinData, $skinModel): bool
{
    $tmp = tempnam('/tmp', 'skin_');
    if (!file_put_contents($tmp, base64_decode($skinData))) {
        return false;
    }
    $info = getimagesize($tmp);
    if ($info[0] != 64
        || ($info[1] != 32 && $info[1] != 64)
        || $info['mime'] !== 'image/png') {
        error_log(print_r(getimagesize($tmp), true));
        return false;
    }
    $conn = dbconn();
    $stmt = $conn->prepare('SELECT skin FROM players WHERE player = ?');
    $stmt->execute([$user]);
    $oldSkin = $stmt->fetchColumn();
    if ($oldSkin && is_readable('./Skins/' . $oldSkin)) {
        unlink('./Skins/' . $oldSkin);
    }
    $newSkin = generate_uuid(false) . generate_uuid(false);

    $stmt = $conn->prepare(
        'UPDATE players SET skin = ?, skin_model = ? WHERE player = ?'
    );
    $stmt->execute([$newSkin, $skinModel, $user]);

    return rename($tmp, './Skins/' . $newSkin);
}
