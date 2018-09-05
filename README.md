# Tencent Could IM SDK

腾讯云的云通信SDK composer版本（仅限于独立模式）。



## 安装

使用 Composer

```json
{
    "require": {
            "lyhiving/tencentcloud-imsdk": "1.0.*"
    }
}
```

## 用法

### 请到 [腾讯云-》云通信](https://console.cloud.tencent.com/avc/list) 选择应用（没有的话需要申请），应用配置中“下载公私钥”，并解压到演示目录。

```php
<?php

use lyhiving\tencentcloud\imsdk;

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

```

## 重点：openssl 这个php的扩展必须安装的。

