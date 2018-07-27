<?php
session_start();

// get data from previous html form
$digits = $_POST['digits'];
$account = $_SESSION['account'];
$password = $_SESSION['password'];
$secret = $_SESSION['secret'];
$qrcode_url = $_SESSION['qrcode'];
//die($qrcode_url);

//$dbhost = '172.16.100.24';
//$dbuser = 'root';
//$dbpass = '11';
//$dbname = 'auth';
//$dbport = '3006';
$dbhost = 'webdavdb';
$dbuser = 'root';
$dbpass = 'admin2153';
$dbname = 'webdav';
//$dbport = '3006';

// 檢查google驗證
function check($secret, $otp_code)
{
    require_once('GoogleAuthenticator.php');
    $ga = new \PHPGangsta_GoogleAuthenticator();
    $is_success = $ga->verifyCode($secret, $otp_code, 1);

    if ($is_success) {
        // 驗證成功
        return true;
    } else {
        // 驗證失敗
        return false;
    }
}


// check google 6 digit if pass then save to db
if (check($secret, $digits)) {
//        $mysqli = new mysqli($dbhost, $dbuser, $dbpass, $dbname, $dbport);
    $mysqli = new mysqli($dbhost, $dbuser, $dbpass, $dbname);
    $mysqli->query("SET NAMES utf8");
    $valid = 0;
    $behashed = $account . ':' . 'SabreDAV' . ':' . $password;
    $hash = md5($behashed);
    $sql = "INSERT INTO `account` (account, password, google, valid) VALUES (?, ?, ?, ?)";
    $stmt = $mysqli->prepare($sql);
    $stmt->bind_param('sssi', $account, $hash, $secret, $valid);
    $stmt->execute();
    $stmt->close();
    $mysqli->close();

    header("Location: finish.html", true, 301);
    exit();
} else {
    echo 'google auth fail please try again!';
//    <meta http-equiv="refresh" content="3;url=exp.html">
    header("Refresh: 4; URL= exp.html?code=" . $qrcode_url, true, 301);
    exit();
}
