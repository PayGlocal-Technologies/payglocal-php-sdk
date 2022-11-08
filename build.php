<?php

$fp = fopen("c3dffc60-bcf8-492d-a747-d46df3d0a483_sitestmid.pem", "r");
//Private Key path

$priv_key = fread($fp, 8192);
fclose($fp);
$privateKey = openssl_get_privatekey($priv_key);


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

$merchantUniqueId = generateRandomString(16);

$payload = json_encode([
    "merchantTxnId" => "23AEE8CB6B62EE2AF07",
    "merchantUniqueId" => $merchantUniqueId,
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
    "merchantCallbackURL" => "https://pwa.meetanshi.com:8890/payglocal/build_response.php" // Response URL
]);

echo '<pre>';
print_r($payload) . '<br>';
echo '</pre>';

openssl_sign($payload, $signature, $privateKey, OPENSSL_ALGO_SHA256);

$sign = base64_encode($signature);
$metadata = json_encode([
    "mid" => "sitestmid", // Merchant ID
    "kid" => "c3dffc60-bcf8-492d-a747-d46df3d0a483" // Private KEy ID
]);


$curl = curl_init();

// UAT Environment url : https://api.uat.payglocal.in/gl/v1/payments/initiate/paycollect
// Production Environment URl : https://api.prod.payglocal.in/gl/v1/payments/initiate/paycollect
// DEV Environment URL : https://api.dev.payglocal.in/gl/v1/payments/initiate/paycollect

curl_setopt_array($curl, array(
    CURLOPT_URL => 'https://api.dev.payglocal.in/gl/v1/payments/initiate/paycollect',
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_ENCODING => '',
    CURLOPT_MAXREDIRS => 10,
    CURLOPT_TIMEOUT => 0,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
    CURLOPT_CUSTOMREQUEST => 'POST',
    CURLOPT_POSTFIELDS => $payload,
    CURLOPT_HTTPHEADER => array(
        'x-gl-sign-external: ' . $sign,
        'x-gl-authn-metadata: ' . $metadata,
        'Content-Type: text/plain'
    ),
));

$response = curl_exec($curl);

$data = json_decode($response, true);

echo '<br>';
//echo "Response:\n";
//echo '<br>';
//echo $response;
//echo '<br>';
echo "Data:\n";
echo '<br>';
print_r($data);
echo '<br>';

curl_close($curl);
?>
<a href="<?php echo $data['data']['redirectUrl']; ?>" target="_blank">Redirect to PayGlocal</a>
