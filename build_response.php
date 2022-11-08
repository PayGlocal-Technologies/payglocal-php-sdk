<?php

$token = $_POST['x-gl-token'];

echo '<pre>';
print_r($_POST);
echo '</pre>';

$data = explode('.', $token);

$payload = base64_decode($data[1]);

$response = json_decode($payload, true);

echo '<pre>';
print_r($response);
echo '</pre>';

$fp = fopen("c3dffc60-bcf8-492d-a747-d46df3d0a483_sitestmid.pem", "r");
//Private Key path
$priv_key = fread($fp, 8192);
fclose($fp);
$privateKey = openssl_get_privatekey($priv_key);

$difPayload = '/gl/v1/payments/' . $response['merchantUniqueId'] . '/status';

openssl_sign($difPayload, $signature, $privateKey, OPENSSL_ALGO_SHA256);

$sign = base64_encode($signature);
$metadata = json_encode([
    "mid" => "sitestmid", // Merchant ID
    "kid" => "c3dffc60-bcf8-492d-a747-d46df3d0a483" // Private KEy ID
]);

// UAT Environment url : https://api.uat.payglocal.in/gl/v1/payments/initiate/paycollect
// Production Environment URl : https://api.prod.payglocal.in/gl/v1/payments/initiate/paycollect
// DEV Environment URL : https://api.dev.payglocal.in/gl/v1/payments/initiate/paycollect

$curl = curl_init();

$url = 'https://api.dev.payglocal.in/gl/v1/payments/' . $response['merchantUniqueId'] . '/status';

curl_setopt_array($curl, array(
    CURLOPT_URL => $url,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_ENCODING => '',
    CURLOPT_MAXREDIRS => 10,
    CURLOPT_TIMEOUT => 0,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
    CURLOPT_HTTPHEADER => array(
        'x-gl-sign-external: ' . $sign,
        'x-gl-authn-metadata: ' . $metadata,
        'Content-Type: text/plain'
    ),
));

$statusResponse = curl_exec($curl);

$statusData = json_decode($statusResponse, true);

curl_close($curl);

echo '<pre>';
print_r($statusData);
echo '</pre>';

if (isset($statusData['status']) && $statusData['status'] == 'SENT_FOR_CAPTURE') {
    // Save gid,status and statusUrl in database and show in order details
    // Process your order and redirect user to checkout success page
} else {
    $error = 'There is a processing error with your transaction ' . $statusData['status'];
    // Order is not completed because order status is not SENT_FOR_CAPTURE and redirect user to cart page
}
