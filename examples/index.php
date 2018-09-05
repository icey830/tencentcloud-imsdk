<?php
include __DIR__ . '/../autoload.php';

use lyhiving\tencentcloud\imsdk;

try{
    $api = new imsdk();
    $api->SetAppid(1400123325); //设置腾讯云云通信应用的appid
    $private = file_get_contents(dirname(__FILE__).DIRECTORY_SEPARATOR.'private_key'); //私钥地址，可以传文本
    var_dump($private);
    $api->SetPrivateKey($private);
    $public = file_get_contents(dirname(__FILE__).DIRECTORY_SEPARATOR.'public_key');//公钥地址，可以传文本
    var_dump($public);
    $api->SetPublicKey($public);
    $sig = $api->genSig('user1');
    $result = $api->verifySig($sig, 'user1', $init_time, $expire_time, $error_msg);
    var_dump(['$sig'=>$sig]); //打印签名
    var_dump($result); //检验结果
    var_dump($init_time);
    var_dump($expire_time);
    var_dump($error_msg);

    $result = $api->verifySig($sig, 'user2', $init_time, $expire_time, $error_msg);
    var_dump($result);
    var_dump($init_time);
    var_dump($expire_time);
    var_dump($error_msg);
}catch(Exception $e){
    echo $e->getMessage();
}