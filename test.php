<?php
require_once 'vendor/autoload.php';

$apiKey = '524d8eb1-68b5-4514-a4ab-96676e31003e';
$apiSecret = '1ED039A13327233A38872DCC1DC55713';
$publicKey = '044455BABDB53E42A73867E5CCDD10CCD6018E317A00F94A31D083D7A82463D747920EA4275BCCD1BB685E64ED1A7FF21D2C6B2EDE8B308FB91E37D57DD5F6DF28';
$privateKey = '152556E12C3C79CE9CF1967DA15D7ABA9B129FD22AACBEDA1CD0C62A731797B4';

$request = new \Z0x\Tzbankopen\Request($apiKey, $apiSecret, $publicKey, $privateKey);

echo "获取token \n";
$token = $request->token("https://ebanktest.tzcb.com:8111/ApiGateWay/auth/getToken");
var_dump($token);

echo "文件上传 \n";
$base64 = 'data:image/png;base64,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';
$attachment = $request->attachment("https://pay.tzcb.com:11117/api/oss/uploadFileTypeMore", $base64);
var_dump($attachment);

echo "交易商户进件(新) \n";
$params = [
    'managerName' => 'test',
    'managerMobile' => '17022221111',
    'busTradeMerNo' => 'Ls001', // 平台商户下唯一UID
    'platMerCstNo' => '8197833247112040502',
    'merType' => '0',
    'tradeMerType' => '0',
    'merCertType' => '22',
    'merName' => 'test',
    'merCertNo' => 'test',
    'corLicenseBatchNo' => '',
    'shortName' => 'test',
    'corCapital' => '0.00',
    'corIdEffectDate' => '2024-01-01',
    'corIdExaDate' => '2028-01-01',
    'merProvinceId' => '',
    'merRegionId' => '',
    'merCountyId' => '',
    'merAddress' => '',
    'busKindCode' => '',
    'corLegName' => 'test',
    'corLegIdType' => '11',
    'corLegNo' => '360720198808080010',
    'corLegIdFaceImgBatchNo' => '',
    'corLegIdBackImgBatchNo' => '',
    'corLegIdEffectDate' => '2024-01-01',
    'corLegIdExaDate' => '2028-01-01',
    'corLegProvince' => '',
    'corLegCity' => '',
    'corLegAdress' => '',
    'settBankAccType' => '0010',
    'settBankAccName' => '叶滔滔',
    'settBankAccNo' => '6224271190394241',
];

var_dump($request->client('https://ebanktest.tzcb.com:8111/ApiGateWay/apihandle/prod/1.0/newTradeEntry', $params, $token['token'], $token['randomSec']));

$params = [
    'orderNo' => time(),
    'orderSource' => '02',
    'trxAmt' => 1,
    'currency' => 'CNY',
    'transType' => '2001',
    'tradeMerCstNo' => '8592241714146578500',
    'platMerCstNo' => '8197833247112040502',
    'businessCstNo' => '123456789',
    'goodsInfo' => '2001',
    'payNotifyUrl' => 'https://www.a.com/notify.php'
];

var_dump($request->client('https://ebanktest.tzcb.com:8111/ApiGateWay/apihandle/prod/1.0/payCreateOrder', $params, $token['token'], $token['randomSec']));