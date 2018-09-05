<?php
namespace lyhiving\tencentcloud;

class imsdk
{

    private $private_key = false;
    private $public_key = false;
    private $appid = 0;
    private $error = '';

    public function __construct()
    {
        if (!extension_loaded('openssl')) {
            trigger_error('need openssl extension', E_USER_ERROR);
        }
        if (!in_array('sha256', openssl_get_md_methods(), true)) {
            trigger_error('need openssl support sha256', E_USER_ERROR);
        }

    }

    /**
     * 获取错误信息
     * @param int $appid
     */
    public function error()
    {
        return $this->error;
    }

    /**
     * 设置Appid
     * @param int $appid
     */
    public function setAppid($appid)
    {
        $this->appid = $appid;
    }

    /**
     * 设置私钥 如果要生成usersig则需要私钥
     * @param string $private_key 私钥文件内容
     * @return bool 是否成功
     * @throws Exception
     */
    public function setPrivateKey($private_key)
    {
        $this->private_key = openssl_pkey_get_private($private_key);
        if ($this->private_key === false) {
            $this->error = openssl_error_string();
            return false;
        }
        return true;
    }

    /**
     * 设置公钥 如果要验证usersig则需要公钥
     * @param string $public_key 公钥文件内容
     * @return bool 是否成功
     * @throws Exception
     */
    public function setPublicKey($public_key)
    {
        $this->public_key = openssl_pkey_get_public($public_key);
        if ($this->public_key === false) {
            $this->error = openssl_error_string();
        }
        return true;
    }

    /**
     * 用于url的base64encode
     * '+' => '*', '/' => '-', '=' => '_'
     * @param string $string 需要编码的数据
     * @return string 编码后的base64串，失败返回false
     * @throws Exception
     */
    private function base64Encode($string)
    {
        static $replace = array('+' => '*', '/' => '-', '=' => '_');
        $base64 = base64_encode($string);
        if ($base64 === false) {
            $this->error = 'base64_encode error';
            return false;
        }
        return str_replace(array_keys($replace), array_values($replace), $base64);
    }

    /**
     * 用于url的base64decode
     * '+' => '*', '/' => '-', '=' => '_'
     * @param string $base64 需要解码的base64串
     * @return string 解码后的数据，失败返回false
     * @throws Exception
     */
    private function base64Decode($base64)
    {
        static $replace = array('+' => '*', '/' => '-', '=' => '_');
        $string = str_replace(array_values($replace), array_keys($replace), $base64);
        $result = base64_decode($string);
        if ($result == false) {
            throw new \Exception('base64_decode error');
        }
        return $result;
    }

    /**
     * 根据json内容生成需要签名的buf串
     * @param array $json 票据json对象
     * @return string 按标准格式生成的用于签名的字符串 失败时返回false
     * @throws Exception
     */
    private function genSignContent(array $json)
    {
        static $members = array(
            'TLS.appid_at_3rd',
            'TLS.account_type',
            'TLS.identifier',
            'TLS.sdk_appid',
            'TLS.time',
            'TLS.expire_after',
        );
        $content = '';
        foreach ($members as $member) {
            if (!isset($json[$member])) {
                $this->error = 'json need ' . $member;
                return false;
            }
            $content .= "{$member}:{$json[$member]}\n";
        }
        return $content;
    }

    /**
     * ECDSA-SHA256签名
     * @param string $data 需要签名的数据
     * @return string 返回签名 失败时返回false
     * @throws Exception
     */
    private function sign($data)
    {
        $signature = '';
        if (!openssl_sign($data, $signature, $this->private_key, 'sha256')) {
            $this->error = openssl_error_string();
            return false;
        }
        return $signature;
    }

    /**
     * 验证ECDSA-SHA256签名
     * @param string $data 需要验证的数据原文
     * @param string $sig 需要验证的签名
     * @return int 1验证成功 0验证失败
     * @throws Exception
     */
    private function verify($data, $sig)
    {
        $ret = openssl_verify($data, $sig, $this->public_key, 'sha256');
        if ($ret == -1) {
            $this->error = openssl_error_string();
            return false;
        }
        return $ret;
    }

    /**
     * 生成usersig
     * @param string $identifier 用户名
     * @param uint $expire usersig有效期 默认为180天
     * @return string 生成的UserSig 失败时为false
     * @throws Exception
     */
    public function genSig($identifier, $expire = 180 * 24 * 3600)
    {
        $json = array(
            'TLS.account_type' => '0',
            'TLS.identifier' => (string) $identifier,
            'TLS.appid_at_3rd' => '0',
            'TLS.sdk_appid' => (string) $this->appid,
            'TLS.expire_after' => (string) $expire,
            'TLS.version' => '201512300000',
            'TLS.time' => (string) time(),
        );
        $err = '';
        $content = $this->genSignContent($json, $err);
        $signature = $this->sign($content, $err);
        $json['TLS.sig'] = base64_encode($signature);
        if ($json['TLS.sig'] === false) {
            $this->error = 'base64_encode error';
            return false;
        }
        $json_text = json_encode($json);
        if ($json_text === false) {
            $this->error = 'json_encode error';
            return false;
        }
        $compressed = gzcompress($json_text);
        if ($compressed === false) {
            $this->error = 'gzcompress error';
            return false;
        }
        return $this->base64Encode($compressed);
    }

    /**
     * 验证usersig
     * @param type $sig usersig
     * @param type $identifier 需要验证用户名
     * @param type $init_time usersig中的生成时间
     * @param type $expire_time usersig中的有效期 如：3600秒
     * @param type $error_msg 失败时的错误信息
     * @return boolean 验证是否成功
     * @throws Exception
     */
    public function verifySig($sig, $identifier, &$init_time, &$expire_time, &$error_msg)
    {
        try {
            $error_msg = '';
            $decoded_sig = $this->base64Decode($sig);
            $uncompressed_sig = gzuncompress($decoded_sig);
            if ($uncompressed_sig === false) {
                $this->error = 'gzuncompress error';
                return false;
            }
            $json = json_decode($uncompressed_sig);
            if ($json == false) {
                $this->error = 'json_decode error';
                return false;
            }
            $json = (array) $json;
            if ($json['TLS.identifier'] !== $identifier) {
                $this->error = "identifier error sigid:{$json['TLS.identifier']} id:{$identifier}";
                return false;
            }
            if ($json['TLS.sdk_appid'] != $this->appid) {
                $this->error = "appid error sigappid:{$json['TLS.appid']} thisappid:{$this->appid}";
                return false;
            }
            $content = $this->genSignContent($json);
            $signature = base64_decode($json['TLS.sig']);
            if ($signature == false) {
                $this->error = 'sig json_decode error';
                return false;
            }
            $succ = $this->verify($content, $signature);
            if (!$succ) {
                $this->error = 'verify failed';
                return false;
            }
            $init_time = $json['TLS.time'];
            $expire_time = $json['TLS.expire_after'];
            return true;
        } catch (Exception $ex) {
            $this->error = $error_msg = $ex->getMessage();
            return false;
        }
    }

}
