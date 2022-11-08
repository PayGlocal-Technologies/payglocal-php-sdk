<?php

require 'vendor/autoload.php';

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Serializer\CompactSerializer as SignatureCompactSerializer;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\JWSLoader;

/*2021-11-15T12:56:18+00:00 INFO (6): Array
(
    [x-gl-token] => eyJpc3N1ZWQtYnkiOiJHbG9jYWwiLCJpcy1kaWdlc3RlZCI6ImZhbHNlIiwiYWxnIjoiUlMyNTYiLCJraWQiOiIxYzJhNGIzNi01NDQ5LTRlZDMtOTBhNi0wYTc5OTk4NzQyMzQifQ.eyJnaWQiOiJnbF9hNjRhMTc2Zi05YmFjLTQxNzAtOTUwZC00ZGM2MjVhMzVjYTkiLCJzdGF0dXNVcmwiOiJodHRwczpcL1wvYXBpLmRldi5wYXlnbG9jYWwuaW5cL2dsXC92MVwvcGF5bWVudHNcL2dsX2E2NGExNzZmLTliYWMtNDE3MC05NTBkLTRkYzYyNWEzNWNhOVwvc3RhdHVzP3gtZ2wtdG9rZW49ZXlKcGMzTjFaV1F0WW5raU9pSkhiRzlqWVd3aUxDSnBjeTFrYVdkbGMzUmxaQ0k2SW1aaGJITmxJaXdpWVd4bklqb2lVbE15TlRZaUxDSnJhV1FpT2lJeFl6SmhOR0l6TmkwMU5EUTVMVFJsWkRNdE9UQmhOaTB3WVRjNU9UazROelF5TXpRaWZRLmV5Sm5hV1FpT2lKbmJGOWhOalJoTVRjMlppMDVZbUZqTFRReE56QXRPVFV3WkMwMFpHTTJNalZoTXpWallUa2lMQ0owZUc1RGRYSnlaVzVqZVNJNklrbE9VaUlzSW5CaGVXWnNiM2N0YTJsa0lqb2lZakpoT0RJelpUSXRORFl3WVMwME16aGlMV0U1WXpFdE56TmhabVJrWlRneU1tWXlJaXdpZEc5MFlXeEJiVzkxYm5RaU9pSXhNQzR3TUNJc0luZ3RaMnd0WTJGeVpDMWpiMnhzWldOMGFXOXVJanAwY25WbExDSnBjMTluYkY5a2FYTndiR0Y1WDJWeWNtOXlJanAwY25WbExDSnRaWEpqYUdGdWRGVnVhWEYxWlVsa0lqb2lORmxJWXpGRmNqTkNaRWxEWjNrMGR5SXNJbTFsY21Ob1lXNTBRMkZzYkdKaFkydFZVa3dpT2lKb2RIUndjenBjTDF3dk1qRmlNemhsWWpZeU55NXVlR05zYVM1dVpYUmNMM0psYzNCdmJuTmxMbkJvY0NJc0ltVjRjQ0k2TXpBd01EQXdMQ0pwWVhRaU9pSXhOak0yT1Rnd09UQTNPREV3SWl3aWVDMW5iQzFuYVdRaU9pSm5iRjloTmpSaE1UYzJaaTA1WW1GakxUUXhOekF0T1RVd1pDMDBaR00yTWpWaE16VmpZVGtpTENKNExXZHNMVzFsY21Ob1lXNTBTV1FpT2lKNWIyZGxjMmhmWkdWdEluMC50TUFnbzZrdHlLUzdXcUU5VXVrR0JGTjNpLXlCMVBGNTZrSHBDRzFFSDlSbUFCcE1NV3BMQjVZTHZtUmJRaFpuYUdqOUg3VGFxcVVOSV8xaWFIUjRKQThWVHRfSTNwb3RBUHJHYVoyVEtiWGZfNU5teU90cVdqNjI4Q2RtQWNqV0N1Wm1VV3pSN1FmTmZqd0hKbEpjTWwxV21LeVNoU1FIRlJRZllKbDNKdXFXVGFvNk5vN0VrM212SHByaFI0WTNFZ2pyWUdfRHQzeXNUQ2JjSTlsdEowd1Zwa3pyMEtzOGNMUVh2N3RNX1dJb0pncmhoX0tjUG1rSW5RWWVELXowX014Z1BFZ1pnLXpfalFrS1Q1dnlIUVpVYTFqOThqQ0Q1UnpFSV9YcjlDQXZEZDhtcjNKcVRQdEotLTdvRnlvZlpmN3FnZ3JFVldfTFgzOXB3Wm8tQlEiLCJtZXJjaGFudFVuaXF1ZUlkIjoiNFlIYzFFcjNCZElDZ3k0dyIsImV4cCI6MzAwMDAwLCJpYXQiOiIxNjM2OTgwOTczMzI3Iiwic3RhdHVzIjoiU0VOVF9GT1JfQ0FQVFVSRSIsIngtZ2wtZ2lkIjoiZ2xfYTY0YTE3NmYtOWJhYy00MTcwLTk1MGQtNGRjNjI1YTM1Y2E5IiwieC1nbC1tZXJjaGFudElkIjoieW9nZXNoX2RlbSJ9.RjNJV1LT8sWNQ_TjBFzRelX_Yx6BmT_aw_e2RQJli40Q8mTyrxcF5v75SSvZ9fJyBUNl5RelCWxOB_wDLQMSHACWpzMRYewYSFe4qfkEtMjvo9WLlh2QPTJ4iiUFdaNyvTgV3xAMPf3LOgwuB0rpNgUkeBidwigGtSJTz0-AdzS0epXjrlbTaa5t2yKVGyPyjBz1TTWzvjqkeqtCVCb6ZyrXKStDHKVFEXLRj6jMG9Y8cOkCsKeer_TqZhmfTC693Sc3r-9ej0j0peiTsYkZMMrwaG3v7SRBtOCKSddjR_QEffIxqkbmPKhe-vAucXiZBByg2goV-G13NW5pdcCkJA
)*/

$params = $_POST;

echo '<pre>';
print_r($params);
echo '</pre>';

$token = $params['x-gl-token'];

$algorithmManager = new AlgorithmManager([
    new RS256(),
]);

$jwsVerifier = new JWSVerifier(
    $algorithmManager
);

$jwk = JWKFactory::createFromKeyFile(
    '832ea6bb-5623-4dc3-96b1-c4be61e97324_PayGlocal_MID.pem', // Public Key Path
    // The filename
    null,
    [
        'kid' => '832ea6bb-5623-4dc3-96b1-c4be61e97324',//Public Key KID,
        'use' => 'sig'
    ]
);

$serializerManager = new JWSSerializerManager([
    new SignatureCompactSerializer(),
]);

$jws = $serializerManager->unserialize($token);
$isVerified = $jwsVerifier->verifyWithKey($jws, $jwk, 0);

if ($isVerified) {
    $headerCheckerManager = $payload = null;

    try {
        $jwsLoader = new JWSLoader(
            $serializerManager,
            $jwsVerifier,
            $headerCheckerManager
        );
    } catch (\Exception $e) {
        throw new $e->getMessage();
    }

    $jws = $jwsLoader->loadAndVerifyWithKey($token, $jwk, $signature, $payload);

    $payload = json_decode($jws->getPayload(), true);

    echo '<pre>';
    print_r($payload);
    echo '</pre>';

    if (isset($payload['status']) && $payload['status'] == 'SENT_FOR_CAPTURE') {
        // Save gid,status and statusUrl in database and show in order details
        // Process your order and redirect user to checkout success page
    } else {
        $error = 'There is a processing error with your transaction ' . $payload['status'];
        // Order is not completed because order status is not SENT_FOR_CAPTURE and redirect user to cart page
    }
} else {
    $errorMsg = 'There is a processing error with your Payglocal payment response verification.';
    // Order is not verified. So, redirect user to cart page with order status.
}


// Will get data in $_POST i have added a token manupulation in test.php file and you will need to check test.php file.
/*2021-11-15T12:56:18+00:00 INFO (6): Array
(
    [x-gl-token] => eyJpc3N1ZWQtYnkiOiJHbG9jYWwiLCJpcy1kaWdlc3RlZCI6ImZhbHNlIiwiYWxnIjoiUlMyNTYiLCJraWQiOiIxYzJhNGIzNi01NDQ5LTRlZDMtOTBhNi0wYTc5OTk4NzQyMzQifQ.eyJnaWQiOiJnbF9hNjRhMTc2Zi05YmFjLTQxNzAtOTUwZC00ZGM2MjVhMzVjYTkiLCJzdGF0dXNVcmwiOiJodHRwczpcL1wvYXBpLmRldi5wYXlnbG9jYWwuaW5cL2dsXC92MVwvcGF5bWVudHNcL2dsX2E2NGExNzZmLTliYWMtNDE3MC05NTBkLTRkYzYyNWEzNWNhOVwvc3RhdHVzP3gtZ2wtdG9rZW49ZXlKcGMzTjFaV1F0WW5raU9pSkhiRzlqWVd3aUxDSnBjeTFrYVdkbGMzUmxaQ0k2SW1aaGJITmxJaXdpWVd4bklqb2lVbE15TlRZaUxDSnJhV1FpT2lJeFl6SmhOR0l6TmkwMU5EUTVMVFJsWkRNdE9UQmhOaTB3WVRjNU9UazROelF5TXpRaWZRLmV5Sm5hV1FpT2lKbmJGOWhOalJoTVRjMlppMDVZbUZqTFRReE56QXRPVFV3WkMwMFpHTTJNalZoTXpWallUa2lMQ0owZUc1RGRYSnlaVzVqZVNJNklrbE9VaUlzSW5CaGVXWnNiM2N0YTJsa0lqb2lZakpoT0RJelpUSXRORFl3WVMwME16aGlMV0U1WXpFdE56TmhabVJrWlRneU1tWXlJaXdpZEc5MFlXeEJiVzkxYm5RaU9pSXhNQzR3TUNJc0luZ3RaMnd0WTJGeVpDMWpiMnhzWldOMGFXOXVJanAwY25WbExDSnBjMTluYkY5a2FYTndiR0Y1WDJWeWNtOXlJanAwY25WbExDSnRaWEpqYUdGdWRGVnVhWEYxWlVsa0lqb2lORmxJWXpGRmNqTkNaRWxEWjNrMGR5SXNJbTFsY21Ob1lXNTBRMkZzYkdKaFkydFZVa3dpT2lKb2RIUndjenBjTDF3dk1qRmlNemhsWWpZeU55NXVlR05zYVM1dVpYUmNMM0psYzNCdmJuTmxMbkJvY0NJc0ltVjRjQ0k2TXpBd01EQXdMQ0pwWVhRaU9pSXhOak0yT1Rnd09UQTNPREV3SWl3aWVDMW5iQzFuYVdRaU9pSm5iRjloTmpSaE1UYzJaaTA1WW1GakxUUXhOekF0T1RVd1pDMDBaR00yTWpWaE16VmpZVGtpTENKNExXZHNMVzFsY21Ob1lXNTBTV1FpT2lKNWIyZGxjMmhmWkdWdEluMC50TUFnbzZrdHlLUzdXcUU5VXVrR0JGTjNpLXlCMVBGNTZrSHBDRzFFSDlSbUFCcE1NV3BMQjVZTHZtUmJRaFpuYUdqOUg3VGFxcVVOSV8xaWFIUjRKQThWVHRfSTNwb3RBUHJHYVoyVEtiWGZfNU5teU90cVdqNjI4Q2RtQWNqV0N1Wm1VV3pSN1FmTmZqd0hKbEpjTWwxV21LeVNoU1FIRlJRZllKbDNKdXFXVGFvNk5vN0VrM212SHByaFI0WTNFZ2pyWUdfRHQzeXNUQ2JjSTlsdEowd1Zwa3pyMEtzOGNMUVh2N3RNX1dJb0pncmhoX0tjUG1rSW5RWWVELXowX014Z1BFZ1pnLXpfalFrS1Q1dnlIUVpVYTFqOThqQ0Q1UnpFSV9YcjlDQXZEZDhtcjNKcVRQdEotLTdvRnlvZlpmN3FnZ3JFVldfTFgzOXB3Wm8tQlEiLCJtZXJjaGFudFVuaXF1ZUlkIjoiNFlIYzFFcjNCZElDZ3k0dyIsImV4cCI6MzAwMDAwLCJpYXQiOiIxNjM2OTgwOTczMzI3Iiwic3RhdHVzIjoiU0VOVF9GT1JfQ0FQVFVSRSIsIngtZ2wtZ2lkIjoiZ2xfYTY0YTE3NmYtOWJhYy00MTcwLTk1MGQtNGRjNjI1YTM1Y2E5IiwieC1nbC1tZXJjaGFudElkIjoieW9nZXNoX2RlbSJ9.RjNJV1LT8sWNQ_TjBFzRelX_Yx6BmT_aw_e2RQJli40Q8mTyrxcF5v75SSvZ9fJyBUNl5RelCWxOB_wDLQMSHACWpzMRYewYSFe4qfkEtMjvo9WLlh2QPTJ4iiUFdaNyvTgV3xAMPf3LOgwuB0rpNgUkeBidwigGtSJTz0-AdzS0epXjrlbTaa5t2yKVGyPyjBz1TTWzvjqkeqtCVCb6ZyrXKStDHKVFEXLRj6jMG9Y8cOkCsKeer_TqZhmfTC693Sc3r-9ej0j0peiTsYkZMMrwaG3v7SRBtOCKSddjR_QEffIxqkbmPKhe-vAucXiZBByg2goV-G13NW5pdcCkJA
)*/


