<?php
session_start();
//header("X-XSS-Protection: 1; mode=block");

//header('X-Frame-Options: SAMEORIGIN');

//header('X-Content-Type-Options: nosniff');

// **PREVENTING SESSION HIJACKING**
// Prevents javascript XSS attacks aimed to steal the session ID
//ini_set('session.cookie_httponly', true);
//
//// **PREVENTING SESSION FIXATION**
//// Session ID cannot be passed through URLs
//ini_set('session.use_only_cookies', true);
//
//// Uses a secure connection (HTTPS) if possible
//ini_set('session.cookie_secure', true);

// perform create a new account
require_once('GoogleAuthenticator.php');
//get POST data from form
$account = $_POST['account'];
$password = $_POST['password'];

$_SESSION['account'] = $account;
$_SESSION['password'] = $password;


// 檢查db確定使用者的名稱存不存在
function check_username($account) {
    // 若存在跳錯誤等4秒後，倒回註冊首頁
    $dbhost = 'webdavdb';
    $dbuser = 'root';
    $dbpass = 'admin2153';
    $dbname = 'webdav';
//    $dbport = '3006';
//    $mysqli = new mysqli($dbhost, $dbuser, $dbpass, $dbname, $dbport);
        $mysqli = new mysqli($dbhost, $dbuser, $dbpass, $dbname);
    $mysqli->query("SET NAMES utf8");
    // todo: fetch from mysql to check
    $sql = "SELECT aId FROM account WHERE account = ?";
    $stmt = $mysqli->prepare($sql);
    $stmt->bind_param('s', $account);
    $stmt->bind_result($from_mysql);
    $stmt->execute();
    if($stmt->fetch())
        $exist = 1;
    else
        $exist = 0;
    $stmt->close();
    $mysqli->close();
    if($exist)
        return true;
    else
        return false;
}

// google auth
$ga = new PHPGangsta_GoogleAuthenticator();
$secret = $ga->createSecret(); // google field save secret
$_SESSION['secret'] = $secret;
$showing = 'ASCDC-WebDAV-' . $account;
$qrcode_url = $ga->getQRCodeGoogleUrl($showing, $secret, $web_url);
$_SESSION['qrcode'] = $qrcode_url;
//echo $qrcode_url.'<br>';

//$dbhost = '172.16.100.24';
//$dbuser = 'root';
//$dbpass = '11';
//$dbname = 'auth';
//$dbport = '3006';
//$mysqli = new mysqli($dbhost, $dbuser, $dbpass, $dbname, $dbport);
//$mysqli->query("SET NAMES utf8");
////$account = 'ascdc';
////$password = 'test';
//$valid = 0;
//$behashed = $account . ':' . 'SabreDAV' . ':' . $password;
////echo $behashed.'<br>';
//$hash = md5($behashed);
////echo $hash;
//$sql = "INSERT INTO `account` (account, password, google, valid) VALUES (?, ?, ?, ?)";
//$stmt = $mysqli->prepare($sql);
//$stmt->bind_param('sssi', $account, $hash, $secret, $valid);
//$stmt->execute();
//$stmt->close();
//$mysqli->close();

if (isset($_POST['g-recaptcha-response']))
    $captcha = $_POST['g-recaptcha-response'];
$response = json_decode(file_get_contents("https://www.google.com/recaptcha/api/siteverify?secret=6LecCmAUAAAAAGVpuEnxOGVUkY_t5Wuri8QKHqO3&response=" . $captcha . "&remoteip=" . $_SERVER['REMOTE_ADDR']), true);
if ($response['success'] == false) {
    echo '<h2>You are spammer ! Get the @$%K out</h2>';
} else {
    // 如果帳號已經存在需有elseif 處理告訴使用者
    if (check_username($account)) {
        echo 'Account has already been existed ! ';
        header("Refresh: 4; URL= index.html", true, 301);
        exit();
    } else {
        header("Location: exp.html?code=" . $qrcode_url, true, 301);
        exit();
    }
    // https://webdav-reg.taieol.tw/register.html
}

?>


