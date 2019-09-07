<?php

function m_login(string $user, string $password): bool
{
    $link = newdb();
    $stmt = $link->prepare('SELECT salt,password FROM players WHERE player = ?');
    $stmt->bind_param('s', $user);
    $stmt->execute();
    $stmt->bind_result($salt, $password2);
    if (!$stmt->fetch()) {
        return false;
    }
    return (salt($salt, $password) === $password2);
}

function m_join(string $accessToken, string $selectedProfile): bool
{
    $link = newdb();
    $stmt = $link->prepare('SELECT accessToken FROM players WHERE accessToken = ?');
    $stmt->bind_param('s', $accessToken);
    $stmt->execute();
    $stmt->bind_result($accessToken2);
    if (!$stmt->fetch()) {
        return false;
    }
    if ($GLOBALS['DEBUG']) {
        error_log('Join OK: ' . $accessToken2);
    }
    return true;
}

function m_isMojang(string $user): bool
{
    $link = newdb();
    $stmt = $link->prepare('SELECT isMojang FROM players WHERE player = ?');
    $stmt->bind_param('s', $user);
    $stmt->execute();
    $stmt->bind_result($isMojang);
    if (!$stmt->fetch()) {
        if ($GLOBALS['DEBUG']) {
            error_log("mojang_hasJoined: {$user} is {$isMojang}");
        }
        return false;
    }
    return (bool) $isMojang;
}

function mojang_hasJoined(string $user, string $serverId)
{
    $link = newdb();
    $stmt = $link->prepare('SELECT accessToken FROM players WHERE player = ?');
    $stmt->bind_param('s', $user);
    $stmt->execute();
    $stmt->bind_result($accessToken);
    if (!$stmt->fetch()) {
        return false;
    }

    $json = file_get_contents(
        "https://sessionserver.mojang.com/session/minecraft/hasJoined?username={$user}&serverId={$serverId}"
    );
    if (strlen($json) === 0) {
        return false;
    }
    $jsonData = json_decode($json, true);
    $jsonData['id'] = $accessToken;
    return json_encode($jsonData);
}

function m_hasJoined(string $user, string $serverId): bool
{
    $link = newdb();
    $stmt = $link->prepare('SELECT serverId FROM players WHERE player = ?');
    $stmt->bind_param('s', $user);
    $stmt->execute();
    $stmt->bind_result($serverId2);
    if (!$stmt->fetch()) {
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
    $link = newdb();
    $stmt = $link->prepare(
        'SELECT reason, who_banned, banned_at FROM banned_players WHERE player = ?'
    );
    $stmt->bind_param('s', $user);
    if (!$stmt->execute()) {
        return false;
    }
    $stmt->bind_result($reason, $whoBanned, $bannedAt);
    if (!$stmt->fetch()) {
        return false;
    }
    return [
        'reason'     => $reason,
        'who_banned' => $whoBanned,
        'banned_at'  => $bannedAt,
    ];
}

function m_ban(string $user, string $target, $reason): bool
{
    $link = newdb();
    $stmt = $link->prepare(
        'INSERT INTO banned_players (player, reason, who_banned) VALUES (?, ?, ?)'
    );
    $stmt->bind_param('sss', $target, $reason, $user);
    if (!$stmt->execute()) {
        error_log('m_ban execute error');
        return false;
    }
    return true;
}

function m_unban(string $user, string $target, string $reason): bool
{
    $link = newdb();
    $stmt = $link->prepare('DELETE FROM banned_players WHERE player = ?');
    $stmt->bind_param('s', $target);
    if (!$stmt->execute()) {
        return false;
    }
    $stmt = $link->prepare(
        'INSERT INTO unbanned_players (player, reason, who_unbanned) VALUES (?, ?, ?)'
    );
    $stmt->bind_param('sss', $target, $reason, $user);
    if (!$stmt->execute()) {
        return false;
    }
    return true;
}

function m_isMod(string $user): bool
{
    $link = newdb();
    $stmt = $link->prepare('SELECT isMod FROM players WHERE player = ?');
    $stmt->bind_param('s', $user);
    if (!$stmt->execute()) {
        return false;
    }
    $stmt->bind_result($isMod);
    if (!$stmt->fetch()) {
        return false;
    }
    return (bool) $isMod;
}

function echo_log(string $line)
{
    if ($GLOBALS['DEBUG']) {
        error_log($line);
    }
    echo $line;
}

function newdb()
{
    $link = new mysqli(
        $GLOBALS['db_host'],
        $GLOBALS['db_username'],
        $GLOBALS['db_password'],
        $GLOBALS['db_name']
    );
    if (mysqli_connect_errno()) {
        error_log('Connection Failed: ' . mysqli_connect_errno());
        die();
    }
    return $link;
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
        $ret = substr_replace($ret, '-',  $pos, 0);
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
    $link = newdb();
    $stmt = $link->prepare('SELECT skin FROM players WHERE player = ?');
    $stmt->bind_param('s', $user);
    $stmt->execute();
    $stmt->bind_result($oldSkin);
    $stmt->fetch();
    $stmt->free_result();
    if ($oldSkin && is_readable('./Skins/' . $oldSkin)) {
        unlink('./Skins/' . $oldSkin);
    }
    $newSkin = generate_uuid(false) . generate_uuid(false);
    $stmt = $link->prepare('UPDATE players SET skin = ?, skin_model = ? WHERE player = ?');
    $stmt->bind_param('sss', $newSkin, $skinModel, $user);
    $stmt->execute();
    if (!rename($tmp, './Skins/' . $newSkin)) {
        return false;
    }
    return true;
}
