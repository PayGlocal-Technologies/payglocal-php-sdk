<?php

//https://web-token.spomky-labs.com/the-components/signed-tokens-jws/jws-creation
//https://web-token.spomky-labs.com/the-components/signed-tokens-jws

//https://github.com/web-token/jwt-framework/

use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CBCHS256;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256KW;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Serializer\CompactSerializer as EncryptionCompactSerializer;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer as SigCompactSerializer;
use Jose\Component\Signature\Algorithm\RS256;


require 'vendor/autoload.php';

function generateRandomString($length = 16)
{
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $charactersLength = strlen($characters);
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, $charactersLength - 1)];
    }
    return $randomString;
}

$keyEncryptionAlgorithmManager = new AlgorithmManager([
    new RSAOAEP256(),
]);
$contentEncryptionAlgorithmManager = new AlgorithmManager([
    new A128CBCHS256(),
]);
$compressionMethodManager = new CompressionMethodManager([
    new Deflate(),
]);

$jweBuilder = new JWEBuilder(
    $keyEncryptionAlgorithmManager,
    $contentEncryptionAlgorithmManager,
    $compressionMethodManager
);

$key = JWKFactory::createFromKeyFile(
    '832ea6bb-5623-4dc3-96b1-c4be61e97324_PayGlocal_MID.pem',
    // The filename
    null,
    [
        'kid' => '832ea6bb-5623-4dc3-96b1-c4be61e97324',
        'use' => 'enc',
        'alg' => 'RSA-OAEP-256',
    ]
);

//print_r($key);

$header = [
    'issued-by' => 'magentodemo',
    'enc' => 'A128CBC-HS256',
    'exp' => 30000,
    'iat' => (string)round(microtime(true) * 1000),
    'alg' => 'RSA-OAEP-256',
    'kid' => '832ea6bb-5623-4dc3-96b1-c4be61e97324'
];

$merchantUniqueId = generateRandomString(16);

$payload = json_encode([
    "merchantTxnId" => "23AEE8CB6B62EE2AF07",
    "merchantUniqueId" => $merchantUniqueId,
    "refundType" => "F",
    "paymentData" => array(
        "totalAmount" => "10.00",
        "txnCurrency" => "INR"
    ),
    "merchantCallbackURL" => "https://www.example.com/payglocal/response.php" // this is our response url. Please check response.php
]);

$jwe = $jweBuilder
    ->create()              // We want to create a new JWE
    ->withPayload($payload) // We set the payload
    ->withSharedProtectedHeader($header)
    ->addRecipient($key)
    ->build();


$serializer = new EncryptionCompactSerializer(); // The serializer
$token = $serializer->serialize($jwe, 0); // We serialize the recipient at index 0 (we only have one recipient).


//echo "JWE Token:\n" . print_r($token, true) . "\n";
//echo '<br>';


$algorithmManager = new AlgorithmManager([
    new RS256(),
]);

$jwsBuilder = new JWSBuilder(
    $algorithmManager
);

$jwskey = JWKFactory::createFromKeyFile(
    '4969a3d1-c840-4e05-8320-408a785c3e5f_magentodemo.pem',  // Public Key Path
    // The filename
    null,
    [
        'kid' => '4969a3d1-c840-4e05-8320-408a785c3e5f', // Public Key ID
        'use' => 'sig'
        //'alg' => 'RSA-OAEP-256',
    ]
);

$jwsheader = [
    'issued-by' => 'magentodemo', // Merchant ID
    'is-digested' => 'true',
    'alg' => 'RS256',
    'x-gl-enc' => 'true',
    'x-gl-merchantId' => 'magentodemo', // Merchant ID
    'kid' => '4969a3d1-c840-4e05-8320-408a785c3e5f' // Public Key ID
];

$hashedPayload = base64_encode(hash('sha256', $token, $BinaryOutputMode = true));

//echo '<br>';
//print_r($hashedPayload) . "\n";
//echo '<br>';

$jwspayload = json_encode([
    'digest' => $hashedPayload,
    'digestAlgorithm' => "SHA-256",
    'exp' => 300000,
    'iat' => (string)round(microtime(true) * 1000)
]);

$jws = $jwsBuilder
    ->create()              // We want to create a new JWS
    ->withPayload($jwspayload) // We set the payload
    ->addSignature($jwskey, $jwsheader)
    ->build();

//print_r($jws);


$jwsserializer = new SigCompactSerializer(); // The serializer
$jwstoken = $jwsserializer->serialize($jws, 0); // We serialize the recipient at index 0 (we only have one recipient).

//echo '<br>';
//echo "JWSToken:\n" . print_r($jwstoken, true) . "\n";
//echo '<br>';


// UAT Environment url : https://api.uat.payglocal.in/gl/v1/payments/
// Production Environment URl : https://api.prod.payglocal.in/gl/v1/

$curl = curl_init();

curl_setopt_array($curl, array(
    CURLOPT_URL => 'https://api.uat.payglocal.in/gl/v1/payments/gl_a64a176f-9bac-4170-950d-4dc625a35ca9/refund',
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_ENCODING => '',
    CURLOPT_MAXREDIRS => 10,
    CURLOPT_TIMEOUT => 0,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
    CURLOPT_CUSTOMREQUEST => 'POST',
    CURLOPT_POSTFIELDS => $token,
    CURLOPT_HTTPHEADER => array(
        'x-gl-token-external: ' . $jwstoken,
        'Content-Type: text/plain'
    ),
));

$response = curl_exec($curl);

$data = json_decode($response, true);

curl_close($curl);

echo '<br>';
//echo "Response:\n";
//echo '<br>';
//echo $response;
//echo '<br>';
//echo "Data:\n";
echo '<br>';
print_r($data);
echo '<br>';


/*Response:
{"gid":"gl_14299664-72da-403a-881f-e0c49a337f32","status":"SENT_FOR_REFUND","message":"Refund request sent successfully","timestamp":"15/11/2021 19:44:34","reasonCode":"GL-201-001","data":{"merchantTxnId":"23AEE8CB6B62EE2AF07","refundCurrency":"INR","refundAmount":"10.00"},"errors":null}
Data:
Array ( [gid] => gl_14299664-72da-403a-881f-e0c49a337f32 [status] => SENT_FOR_REFUND [message] => Refund request sent successfully [timestamp] => 15/11/2021 19:44:34 [reasonCode] => GL-201-001 [data] => Array ( [merchantTxnId] => 23AEE8CB6B62EE2AF07 [refundCurrency] => INR [refundAmount] => 10.00 ) [errors] => )*/

?>



