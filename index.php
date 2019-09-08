<?php
require 'config.php';
require 'functions.php';

$json = file_get_contents('php://input');
$jsonData = json_decode($json, true);

(empty($_GET['act'])) && die('wat');
(!ini_get('date.timezone')) && date_default_timezone_set('UTC');
$skinDate = ((time() * 1000));

switch ($_GET['act']) {
    case 'login':
        if (empty($jsonData['username']) || empty($jsonData['password'])
            || empty($jsonData['ticket']) || empty($jsonData['launcherVersion'])
            || empty($jsonData['platform'])) {
            die(echo_log(json_encode([
                'error'        => 'Bad request',
                'errorMessage' => 'Bad request',
                'cause'        => 'Bad request',
            ])));
        }
        if (!m_login($jsonData['username'], $jsonData['password'])) {
            header('HTTP/1.1 401 Unauthorized');
            $error = [
                'error'        => 'Unauthorized',
                'errorMessage' => 'Unauthorized',
                'cause'        => 'Wrong username/password',
            ];
            die(echo_log(json_encode($error)));
        }
        $status = m_checkban($jsonData['username']);
        if ($status) {
            $answer = [
                'error'        => 'ban',
                'errorMessage' => $jsonData['username'] . ' have been banned by '
                                . $status['who_banned'] . ' Reason: ' . $status['reason'],
            ];
            die(echo_log(json_encode($answer)));
        }
        header('HTTP/1.1 200 OK');
        $conn = dbconn();

        $stmt = $conn->prepare(
            'SELECT clientToken, accessToken FROM players WHERE player = ?'
        );
        $stmt->execute([$jsonData['username']]);
        list($clientToken, $accessToken) = $stmt->fetch();

        $stmt = $conn->prepare(
            'INSERT INTO ids (player, ip, ticket, launcher_ver, os, os_arch, os_version) ' .
            'VALUES (?, ?, ?, ?, ?, ?, ?)'
        );
        $stmt->bindParam(1, $jsonData['username'], PDO::PARAM_STR);
        $stmt->bindParam(2, $_SERVER['REMOTE_ADDR'], PDO::PARAM_STR);
        $stmt->bindParam(3, $jsonData['ticket'], PDO::PARAM_STR);
        $stmt->bindParam(4, $jsonData['launcherVersion'], PDO::PARAM_STR);
        $stmt->bindParam(5, $jsonData['platform']['os'], PDO::PARAM_STR);
        $stmt->bindParam(6, $jsonData['platform']['word'], PDO::PARAM_STR);
        $stmt->bindParam(7, $jsonData['platform']['version'], PDO::PARAM_STR);
        $stmt->execute();
        $answer = [
            'accessToken'       => $accessToken,
            'clientToken'       => $clientToken,
            'availableProfiles' => [[
                'id'     => $clientToken,
                'name'   => $jsonData['username'],
                'legacy' => false,
            ]],
            'selectedProfile' => [
                'id'     => $clientToken,
                'name'   => $jsonData['username'],
                'legacy' => false,
            ],
        ];
        echo_log(json_encode($answer));
        break;

    case 'setskin':
        if (empty($jsonData['username'])
            || empty($jsonData['password'])
            || empty($jsonData['skinData'])) {
            die(echo_log(json_encode([
                'error'        => 'Bad request',
                'errorMessage' => 'Bad request',
                'cause'        => 'Bad request',
            ])));
        }
        if (!m_login($jsonData['username'], $jsonData['password'])) {
            die(echo_log(json_encode(['error' => 'Bad login'])));
        }
        if (set_skin($jsonData['username'], $jsonData['skinData'], $jsonData['skinModel'] ?? null)) {
            $answer = ['username' => $jsonData['username'], 'status' => 'accepted'];
        } else {
            $answer = ['error' => 'Bad request'];
        }
        echo_log(json_encode($answer));
        break;

    case stripos($_GET['act'], 'skin/') === 0:
        $begin = strpos($_GET['act'], '/');
        $end = strrpos($_GET['act'], '.');
        if ($begin === false || $end === false) {
            header('HTTP/1.0 404 Not Found');
            break;
        }

        $name = substr($_GET['act'], $begin + 1, ($end - $begin - 1));
        $conn = dbconn();
        $stmt = $conn->prepare('SELECT skin FROM players WHERE player = ?');
        $stmt->execute([$name]);
        $skin = $stmt->fetchColumn();

        header('Location: ' . $http_root . '/Skins/' . ($skin ?? 'fairy'));
        break;

    case 'join':
        if (empty($jsonData['accessToken'])
            || empty($jsonData['selectedProfile'])
            || empty($jsonData['serverId'])) {
            die('Bad request');
        }
        if (!m_join($jsonData['accessToken'], $jsonData['selectedProfile'])) {
            break;
        }
        $conn = dbconn();
        $stmt = $conn->prepare(
            'UPDATE players SET serverId = ? WHERE accessToken = ?'
        );
        $stmt->execute([$jsonData['serverId'], $jsonData['accessToken']]);
        break;

    case 'hasJoined':
        if (empty($_GET['username']) || empty($_GET['serverId'])) {
            die('Bad request');
        }
        $status = m_checkban($_GET['username']);
        if ($status) {
            $answer = [
                'username' => $_GET['username'],
                'status'   => 'banned',
                'info'     => $status,
            ];
            die(echo_log(json_encode($answer)));
        }
        if (m_isMojang($_GET['username'])) {
            $answer = mojang_hasJoined($_GET['username'], $_GET['serverId']);
            if (strlen($answer) === 0) {
                break;
            }
            echo_log($answer);
            break;
        } else {
            if (!m_hasJoined($_GET['username'], $_GET['serverId'])) {
                die();
            }
        }
        header('HTTP/1.1 200 OK');

        $conn = dbconn();
        $stmt = $conn->prepare(
            'SELECT clientToken, cape, skin, skin_model FROM players WHERE player = ?'
        );
        $stmt->execute([$_GET['username']]);

        $result = $stmt->fetch();
        if ($result === false) {
            break;
        }
        list($clientToken, $cape, $skin, $skin_model) = $result;

        if (!$skin) {
            $skin = 'fairy'; // default skin
        }
        $value = [
            'timestamp'   => $skinDate,
            'profileId'   => $clientToken,
            'profileName' => $_GET['username'],
        ];
        $value['textures'] = [];
        if ($skin) {
            $value['textures']['SKIN'] = ['url' => $http_root . '/Skins/' . $skin];
            if ($skin_model) {
                $value['textures']['SKIN']['metadata'] = ['model' => $skin_model];
            }
        }
        if ($cape) {
            $value['textures']['CAPE'] = ['url' => $http_root . '/Capes/' . $cape];
        }
        $value = json_encode($value, JSON_UNESCAPED_SLASHES);
        $fp = fopen('./key.pem', 'r');
        $privKey = fread($fp, filesize('./key.pem'));
        fclose($fp);
        $pk = openssl_pkey_get_private($privKey);
        openssl_sign(base64_encode($value), $signature, $pk);
        $answer = [
            'id'         => $clientToken,
            'name'       => $_GET['username'],
            'properties' => [[
                'name'      => 'textures',
                'value'     => base64_encode($value),
                'signature' => base64_encode($signature),
            ]],
        ];
        echo_log(json_encode($answer, JSON_UNESCAPED_SLASHES));
        break;

    case stripos($_GET['act'], 'profile/') === 0:
        list(, $id, ) = explode('/', $_GET['act'], 3);

        $uuid = to_uuid($id);
        if (is_null($uuid)) {
            break;
        }

        $conn = dbconn();
        $stmt = $conn->prepare(
            'SELECT player, cape, skin, skin_model FROM players WHERE clientToken = ?'
        );
        $stmt->execute([$uuid]);
        $result = $stmt->fetch();
        if ($result === false) {
            break;
        }
        list($player, $cape, $skin, $skin_model) = $result;

        if (!$skin) {
            $skin = 'fairy'; // default skin
        }
        $value = [
            'timestamp'   => $skinDate,
            'profileId'   => $uuid,
            'profileName' => $player,
        ];
        $value['textures'] = [];
        if ($skin) {
            $value['textures']['SKIN'] = ['url' => $http_root . '/Skins/' . $skin];
            if ($skin_model) {
                $value['textures']['SKIN']['metadata'] = ['model' => $skin_model];
            }
        }
        if ($cape) {
            $value['textures']['CAPE'] = ['url' => $http_root . '/Capes/' . $cape];
        }
        $value = json_encode($value, JSON_UNESCAPED_SLASHES);
        $fp = fopen('./key.pem', 'r');
        $privKey = fread($fp, filesize('./key.pem'));
        fclose($fp);
        $pk = openssl_pkey_get_private($privKey);
        openssl_sign(base64_encode($value), $signature, $pk);
        $answer = [
            'id'         => $uuid,
            'name'       => $player,
            'properties' => [[
                'name'      => 'textures',
                'value'     => base64_encode($value),
                'signature' => base64_encode($signature),
            ]],
        ];
        echo_log(json_encode($answer, JSON_UNESCAPED_SLASHES));
        break;

    case stripos($_GET['act'], 'users/profiles/minecraft/') === 0:
        $name = substr($_GET['act'], strlen('users/profiles/minecraft/'));
        list($name, ) = explode('?', $name, 2);
        $conn = dbconn();
        $stmt = $conn->prepare('SELECT clientToken FROM players WHERE player = ?');
        $stmt->execute([$name]);
        $id = $stmt->fetchColumn();
        if ($id === false) {
            header('HTTP/1.0 204 No Response');
            break;
        }
        $answer = ['id' => str_replace('-', '', $id), 'name' => $name];
        echo_log(json_encode($answer, JSON_UNESCAPED_SLASHES));
        break;

    case stripos($_GET['act'], 'profiles/minecraft') === 0:
        if (count($jsonData) > 100) {
            echo_log(json_encode([
                'error' => 'Too many',
                'errorMessage' => 'Error',
                'cause' => 'over100',
            ]));
            break;
        }
        $answer = [];
        $conn = dbconn();
        $stmt = $conn->prepare('SELECT clientToken FROM players WHERE player = ?');

        foreach ($jsonData as $name) {
            $stmt->execute([$name]);
            $id = $stmt->fetchColumn();
            if ($id !== false) {
                $answer[] = ['id' => str_replace('-', '', $id), 'name' => $name];
            }
        }
        echo_log(json_encode($answer, JSON_UNESCAPED_SLASHES));
        break;

    case 'chpass':
        echo_log(json_encode([
            'error'        => 'Use forum',
            'errorMessage' => 'Error',
            'cause'        => 'Internal error',
        ]));
        break;

    case 'ban':
        if (empty($_GET['username'])
            || empty($_GET['password'])
            || empty($_GET['target'])
            || empty($_GET['reason'])) {
            die('Bad request');
        }
        if (!m_login($_GET['username'], $_GET['password'])) {
            header('HTTP/1.1 401 Unauthorized');
            $error = [
                'error'        => 'Unauthorized',
                'errorMessage' => 'Unauthorized',
                'cause'        => 'Wrong username/password',
            ];
            die(echo_log(json_encode($error)));
        }
        if ((!m_isMod($_GET['username']) || m_checkban($_GET['username']))) {
            header('HTTP/1.1 401 Unauthorized');
            $error = [
                'error'        => 'Unauthorized',
                'errorMessage' => 'Unauthorized',
                'cause'        => 'Permission denied',
            ];
            die(echo_log(json_encode($error)));
        }
        $status = m_checkban($_GET['target']);
        if ($status) {
            $answer = [
                'username' => $_GET['target'],
                'status'   => 'banned',
                'info'     => $status,
            ];
            die(echo_log(json_encode($answer)));
        }
        if (!m_ban($_GET['username'], $_GET['target'], $_GET['reason'])) {
            header('HTTP/1.1 500 Internal Server Error');
            $answer = [
                'error'        => 'Error',
                'errorMessage' => 'Error',
                'cause'        => 'Internal error',
            ];
        } else {
            header('HTTP/1.1 200 OK');
            $answer = [
                'target' => $_GET['target'],
                'reason' => $_GET['reason'],
            ];
        }
        echo_log(json_encode($answer));
        break;

    case 'unban':
        if (empty($_GET['username'])
            || empty($_GET['password'])
            || empty($_GET['target'])
            || empty($_GET['reason'])) {
            die('Bad request');
        }
        if (!m_login($_GET['username'], $_GET['password'])) {
            header('HTTP/1.1 401 Unauthorized');
            $error = [
                'error'        => 'Unauthorized',
                'errorMessage' => 'Unauthorized',
                'cause'        => 'Wrong username/password',
            ];
            die(echo_log(json_encode($error)));
        }
        if ((!m_isMod($_GET['username']) || m_checkban($_GET['username']))) {
            header('HTTP/1.1 401 Unauthorized');
            $error = [
                'error'        => 'Unauthorized',
                'errorMessage' => 'Unauthorized',
                'cause'        => 'Permission denied',
            ];
            die(echo_log(json_encode($error)));
        }
        $status = m_checkban($_GET['target']);
        if (!$status) {
            die(echo_log(json_encode([
                'username' => $_GET['target'],
                'status'   => 'not banned',
            ])));
        }
        if (!m_unban($_GET['username'], $_GET['target'], $_GET['reason'])) {
            $answer = [
                'error'        => 'Error',
                'errorMessage' => 'Error',
                'cause'        => 'Internal error',
            ];
        } else {
            $answer = ['target' => $_GET['target'], 'status' => 'unbanned'];
        }
        echo_log(json_encode($answer));
        break;

    case 'checkban':
        if (empty($_GET['username'])) {
            die('Bad request');
        }
        $status = m_checkban($_GET['username']);
        if (!$status) {
            $answer = [
                'username' => $_GET['username'],
                'status'   => 'not banned',
            ];
        } else {
            $answer = [
                'username' => $_GET['username'],
                'status'   => 'banned',
                'info'     => $status,
            ];
        }
        echo_log(json_encode($answer));
        break;

    case 'feedback':
        if (empty($jsonData['username']) || empty($jsonData['password'])) {
            die(echo_log(json_encode([
                'error'        => 'Bad request',
                'errorMessage' => 'Bad request',
                'cause'        => 'Bad request',
            ])));
        }
        if (!m_login($jsonData['username'], $jsonData['password'])) {
            die(json_encode([
                'error' => 'Unauthorized',
                'errorMessage' => 'Unauthorized',
                'cause' => 'Wrong username/password',
            ]));
        }
        $logfile = './feedback/' . $jsonData['username'] . '.'
            . date('Y-m-d_H-i-s_') . explode(' ', microtime(), 2)[0] . '.log';
        if (file_put_contents($logfile, gzdecode(base64_decode($jsonData['log'])))
            || file_put_contents($logfile, base64_decode($jsonData['desc']) . "\n" . base64_decode($jsonData['log']) . "\n")) {
            $answer = ['username' => $jsonData['username'], 'status' => 'accepted'];
        } else {
            $answer = ['username' => $jsonData['username'], 'status' => 'not accepted'];
        }
        echo_log(json_encode($answer));
        break;

    default:
        die("I'm sorry, what?");
}
