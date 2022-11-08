<?php

//https://web-token.spomky-labs.com/the-components/signed-tokens-jws/jws-creation
//https://web-token.spomky-labs.com/the-components/signed-tokens-jws
//https://github.com/web-token/jwt-framework/
// FOR PHP 7.1
//composer require web-token/jwt-framework:1.3 --ignore-platform-reqs

// FOR PHP 7.2-7.4
//composer require web-token/jwt-framework:2.2 --ignore-platform-reqs

// FOR PHP 8.0
//composer require web-token/jwt-framework --ignore-platform-reqs

require 'vendor/autoload.php';

use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CBCHS256;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Algorithm\RS256;

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
        'kid' => '832ea6bb-5623-4dc3-96b1-c4be61e97324',//Public Key KID
        'use' => 'enc',
        'alg' => 'RSA-OAEP-256',
    ]
);

//print_r($key);

$header = [
    'issued-by' => 'magentodemo',//Merchant ID
    'enc' => 'A128CBC-HS256',
    'exp' => 30000,
    'iat' => (string)round(microtime(true) * 1000),
    'alg' => 'RSA-OAEP-256',
    'kid' => '832ea6bb-5623-4dc3-96b1-c4be61e97324'//Public Key KID
];

$merchantUniqueId = generateRandomString(16);

$payload = json_encode([
    "merchantTxnId" => "23AEE8CB6B62EE2AF07", // Order Increment ID
    "merchantUniqueId" => $merchantUniqueId, // Unique Random key and must be 16 digit long
    "paymentData" => array(
        "totalAmount" => "10.00",
        "txnCurrency" => "INR",
        "billingData" => array(
            "firstName" => "John",
            "lastName" => "Denver",
            "addressStreet1" => "Rowley street 1",
            "addressStreet2" => "Punctuality lane",
            "addressCity" => "Bangalore",
            "addressState" => "Karnataka",
            "addressPostalCode" => "560094",
            "addressCountry" => "IN",
            "emailId" => "johndenver@myemail.com"
        )
    ),
    "merchantCallbackURL" => "https://www.example.com/payglocal/response.php"// Response url. please check response.php for response handling
]);

$jwe = $jweBuilder
    ->create()              // We want to create a new JWE
    ->withPayload($payload) // We set the payload
    ->withSharedProtectedHeader($header)
    ->addRecipient($key)
    ->build();


$serializer = new CompactSerializer(); // The serializer
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
    '4969a3d1-c840-4e05-8320-408a785c3e5f_magentodemo.pem', // Private Key Path
    // The filename
    null,
    [
        'kid' => '4969a3d1-c840-4e05-8320-408a785c3e5f', // Private Key ID
        'use' => 'sig'
        //'alg' => 'RSA-OAEP-256',
    ]
);

$jwsheader = [
    'issued-by' => 'magentodemo', // Merchant ID
    'is-digested' => 'true',
    'alg' => 'RS256',
    'x-gl-enc' => 'true',
    'x-gl-merchantId' => 'magentodemo',// Merchant ID
    'kid' => '4969a3d1-c840-4e05-8320-408a785c3e5f' // Private Key ID
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


$jwsserializer = new \Jose\Component\Signature\Serializer\CompactSerializer(); // The serializer
$jwstoken = $jwsserializer->serialize($jws, 0); // We serialize the recipient at index 0 (we only have one recipient).

//echo '<br>';
//echo "JWSToken:\n" . print_r($jwstoken, true) . "\n";
//echo '<br>';

$curl = curl_init();

// UAT Environment url : https://api.uat.payglocal.in/gl/v1/payments/initiate/paycollect
// Production Environment URl : https://api.prod.payglocal.in/gl/v1/payments/initiate/paycollect

curl_setopt_array($curl, array(
    CURLOPT_URL => 'https://api.uat.payglocal.in/gl/v1/payments/initiate/paycollect',
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

//echo '<br>';
//echo "Response:\n";
//echo '<br>';
//echo $response;
//echo '<br>';
//echo "Data:\n";
//echo '<br>';
//print_r($data);
//echo '<br>';

?>
<a href="<?php echo $data['data']['redirectUrl'];?>" target="_blank">Redirect to PayGlocal</a>


