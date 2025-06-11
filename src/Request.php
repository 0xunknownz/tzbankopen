<?php

namespace Z0x\Tzbankopen;

use HTTP_Request2;
use Ramsey\Uuid\Uuid;
use Rtgm\sm\RtSm2;
use Rtgm\sm\RtSm3;

class Request
{
    private $appKey;
    private $appSecret;
    private $publicKey;
    private $privateKey;

    public function __construct($appKey, $appSecret, $publicKey, $privateKey)
    {
        $this->appKey = $appKey;
        $this->appSecret = $appSecret;
        $this->publicKey = $publicKey;
        $this->privateKey = $privateKey;
    }

    public function token($requestUrl)
    {
        $sm2 = new RtSm2('hex', true);
        $sm3 = new RtSm3();
        $sm4 = new SM4();
        $uuid = $this->getGUID();
        $tranDate = date("Y-m-d H:i:s.v");
        $inputDic = array("equUniSeqNo" => 'cs', "randomSec" => $uuid, "tranDate" => $tranDate);
        $sm3Sign = $sm3->digest(json_encode($inputDic, JSON_UNESCAPED_UNICODE));
        $sign = $sm2->doSign(hex2bin($sm3Sign), $this->privateKey, hex2bin("1234567812345678"));
        $inputDic['x-sign'] = $sign;
        $eyInputAndSignJson = $sm4->setKey($this->appSecret)->encryptData(json_encode($inputDic, JSON_UNESCAPED_UNICODE));
        $headerMap = array("x-appKey" => $this->appKey, "Content-Type" => "application/json");
        $result = $this->post($requestUrl, $eyInputAndSignJson, $headerMap);
        return json_decode($sm4->setKey($this->appSecret)->decryptData(str_replace("\n", "", $result["returnJson"])), JSON_UNESCAPED_UNICODE);
    }

    public function getGUID()
    {
        $uuid = Uuid::uuid4(); // 生成UUID v4
        return strtoupper(md5($uuid, false));
    }

    protected function post($requestUrl, $message, $header)
    {
        $request = new HTTP_Request2();
        $request->setUrl($requestUrl);
        $request->setMethod(HTTP_Request2::METHOD_POST);
        $request->setConfig(array(
            'ssl_verify_peer' => FALSE,
            'ssl_verify_host' => FALSE,
        ));
        $header['Content-Type'] = 'application/json';
        $request->setHeader($header);
        $request->setBody($message);

        $response = $request->send();
        if ($response->getStatus() == 200) {
            $resultDic = array("isSuccess" => true, 'returnJson' => $response->getBody());
        } elseif ($response->getStatus() == 601) {
            $url64 = urldecode($response->getHeader("errBody"));
            $resultDic = array("isSuccess" => false, 'returnJson' => base64_decode($url64));
        } else {
            $resultDic = array("isSuccess" => false, 'returnJson' => $response->getBody());
        }

        return $resultDic;
    }

    public function client($requestUrl, $params, $token, $randomSec)
    {
        $sm2 = new RtSm2('hex', true);
        $sm3 = new RtSm3();
        $sm4 = new SM4();

        $data = [
            'reqHeader' => [
                'tranDate' => date("Y-m-d"),
                'tranTime' => date("H:i:s.v"),
                'cutType' => 'WEB',
                'tranSeq' => $this->getGUID(),
                'terminalNo' => '123456789'
            ],
            'reqBody' => $params,
        ];
        $data['token'] = $token;
        $inputAndToken = json_encode($data, JSON_UNESCAPED_UNICODE);
        $inputAndToken = str_replace("\\", "", $inputAndToken);
        $sm3Sign = $sm3->digest($inputAndToken);
        $sign = $sm2->doSign(hex2bin($sm3Sign), $this->privateKey, hex2bin("1234567812345678"));
        $data['x-sign'] = $sign;
        $headerMap = array("x-appKey" => $this->appKey, "token" => $token);
        $sm4inputS = $sm4->setKey($randomSec)->encryptData(json_encode($data));

        $result = $this->post($requestUrl, $sm4inputS, $headerMap);
        return json_decode($sm4->setKey($this->appSecret)->decryptData(str_replace("\n", "", $result["returnJson"])), JSON_UNESCAPED_UNICODE);
    }

    public function attachment($requestUrl, $base64Image, $filename = 'image.png')
    {
        // 解码 Base64 并写入临时文件
        $imageData = base64_decode($base64Image);
        $tmpFile = tempnam(sys_get_temp_dir(), 'upload_');
        file_put_contents($tmpFile, $imageData);

        // 创建请求
        $request = new \HTTP_Request2();
        $request->setUrl($requestUrl);
        $request->setMethod(\HTTP_Request2::METHOD_POST);
        $request->setConfig([
            'ssl_verify_peer' => false,
            'ssl_verify_host' => false,
        ]);

        $request->setHeader([
            'Content-Type' => 'multipart/form-data'
        ]);

        // 添加上传文件（注意提供真实文件名）
        $request->addUpload('file', $tmpFile, $filename, 'image/png');

        // 发起请求
        $response = $request->send();

        // 清理临时文件
        unlink($tmpFile);

        return json_decode($response->getBody(), true);
    }
}