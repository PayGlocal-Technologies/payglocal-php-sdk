<?php











namespace Composer;

use Composer\Autoload\ClassLoader;
use Composer\Semver\VersionParser;






class InstalledVersions
{
private static $installed = array (
  'root' => 
  array (
    'pretty_version' => '1.0.0+no-version-set',
    'version' => '1.0.0.0',
    'aliases' => 
    array (
    ),
    'reference' => NULL,
    'name' => '__root__',
  ),
  'versions' => 
  array (
    '__root__' => 
    array (
      'pretty_version' => '1.0.0+no-version-set',
      'version' => '1.0.0.0',
      'aliases' => 
      array (
      ),
      'reference' => NULL,
    ),
    'fgrosse/phpasn1' => 
    array (
      'pretty_version' => 'v2.4.0',
      'version' => '2.4.0.0',
      'aliases' => 
      array (
      ),
      'reference' => 'eef488991d53e58e60c9554b09b1201ca5ba9296',
    ),
    'paragonie/random_compat' => 
    array (
      'pretty_version' => 'v9.99.100',
      'version' => '9.99.100.0',
      'aliases' => 
      array (
      ),
      'reference' => '996434e5492cb4c3edcb9168db6fbb1359ef965a',
    ),
    'paragonie/sodium_compat' => 
    array (
      'pretty_version' => 'v1.17.1',
      'version' => '1.17.1.0',
      'aliases' => 
      array (
      ),
      'reference' => 'ac994053faac18d386328c91c7900f930acadf1e',
    ),
    'psr/cache' => 
    array (
      'pretty_version' => '2.0.0',
      'version' => '2.0.0.0',
      'aliases' => 
      array (
      ),
      'reference' => '213f9dbc5b9bfbc4f8db86d2838dc968752ce13b',
    ),
    'psr/cache-implementation' => 
    array (
      'provided' => 
      array (
        0 => '1.0|2.0',
      ),
    ),
    'psr/container' => 
    array (
      'pretty_version' => '1.1.2',
      'version' => '1.1.2.0',
      'aliases' => 
      array (
      ),
      'reference' => '513e0666f7216c7459170d56df27dfcefe1689ea',
    ),
    'psr/container-implementation' => 
    array (
      'provided' => 
      array (
        0 => '1.0',
      ),
    ),
    'psr/event-dispatcher-implementation' => 
    array (
      'provided' => 
      array (
        0 => '1.0',
      ),
    ),
    'psr/log' => 
    array (
      'pretty_version' => '2.0.0',
      'version' => '2.0.0.0',
      'aliases' => 
      array (
      ),
      'reference' => 'ef29f6d262798707a9edd554e2b82517ef3a9376',
    ),
    'psr/log-implementation' => 
    array (
      'provided' => 
      array (
        0 => '1.0|2.0',
      ),
    ),
    'psr/simple-cache-implementation' => 
    array (
      'provided' => 
      array (
        0 => '1.0|2.0',
      ),
    ),
    'spomky-labs/aes-key-wrap' => 
    array (
      'pretty_version' => 'v5.0.0',
      'version' => '5.0.0.0',
      'aliases' => 
      array (
      ),
      'reference' => '7e5c5bef68a08d0c474e6ff6d5b63d12e023b3b2',
    ),
    'spomky-labs/base64url' => 
    array (
      'pretty_version' => 'v2.0.4',
      'version' => '2.0.4.0',
      'aliases' => 
      array (
      ),
      'reference' => '7752ce931ec285da4ed1f4c5aa27e45e097be61d',
    ),
    'symfony/cache' => 
    array (
      'pretty_version' => 'v5.4.9',
      'version' => '5.4.9.0',
      'aliases' => 
      array (
      ),
      'reference' => 'a50b7249bea81ddd6d3b799ce40c5521c2f72f0b',
    ),
    'symfony/cache-contracts' => 
    array (
      'pretty_version' => 'v2.5.1',
      'version' => '2.5.1.0',
      'aliases' => 
      array (
      ),
      'reference' => '64be4a7acb83b6f2bf6de9a02cee6dad41277ebc',
    ),
    'symfony/cache-implementation' => 
    array (
      'provided' => 
      array (
        0 => '1.0|2.0',
      ),
    ),
    'symfony/config' => 
    array (
      'pretty_version' => 'v4.4.42',
      'version' => '4.4.42.0',
      'aliases' => 
      array (
      ),
      'reference' => '83cdafd1bd3370de23e3dc2ed01026908863be81',
    ),
    'symfony/console' => 
    array (
      'pretty_version' => 'v4.4.42',
      'version' => '4.4.42.0',
      'aliases' => 
      array (
      ),
      'reference' => 'cce7a9f99e22937a71a16b23afa762558808d587',
    ),
    'symfony/debug' => 
    array (
      'pretty_version' => 'v4.4.41',
      'version' => '4.4.41.0',
      'aliases' => 
      array (
      ),
      'reference' => '6637e62480b60817b9a6984154a533e8e64c6bd5',
    ),
    'symfony/dependency-injection' => 
    array (
      'pretty_version' => 'v4.4.42',
      'version' => '4.4.42.0',
      'aliases' => 
      array (
      ),
      'reference' => 'f6fdbf252765a09c7ac243617f79f1babef792c9',
    ),
    'symfony/deprecation-contracts' => 
    array (
      'pretty_version' => 'v3.1.0',
      'version' => '3.1.0.0',
      'aliases' => 
      array (
      ),
      'reference' => '07f1b9cc2ffee6aaafcf4b710fbc38ff736bd918',
    ),
    'symfony/error-handler' => 
    array (
      'pretty_version' => 'v4.4.41',
      'version' => '4.4.41.0',
      'aliases' => 
      array (
      ),
      'reference' => '529feb0e03133dbd5fd3707200147cc4903206da',
    ),
    'symfony/event-dispatcher' => 
    array (
      'pretty_version' => 'v4.4.42',
      'version' => '4.4.42.0',
      'aliases' => 
      array (
      ),
      'reference' => '708e761740c16b02c86e3f0c932018a06b895d40',
    ),
    'symfony/event-dispatcher-contracts' => 
    array (
      'pretty_version' => 'v1.1.12',
      'version' => '1.1.12.0',
      'aliases' => 
      array (
      ),
      'reference' => '1d5cd762abaa6b2a4169d3e77610193a7157129e',
    ),
    'symfony/event-dispatcher-implementation' => 
    array (
      'provided' => 
      array (
        0 => '1.1',
      ),
    ),
    'symfony/filesystem' => 
    array (
      'pretty_version' => 'v5.4.9',
      'version' => '5.4.9.0',
      'aliases' => 
      array (
      ),
      'reference' => '36a017fa4cce1eff1b8e8129ff53513abcef05ba',
    ),
    'symfony/finder' => 
    array (
      'pretty_version' => 'v5.4.8',
      'version' => '5.4.8.0',
      'aliases' => 
      array (
      ),
      'reference' => '9b630f3427f3ebe7cd346c277a1408b00249dad9',
    ),
    'symfony/framework-bundle' => 
    array (
      'pretty_version' => 'v4.4.42',
      'version' => '4.4.42.0',
      'aliases' => 
      array (
      ),
      'reference' => '24129749500ba6e9b1b2a75622323b4ce23d7b23',
    ),
    'symfony/http-client-contracts' => 
    array (
      'pretty_version' => 'v2.5.1',
      'version' => '2.5.1.0',
      'aliases' => 
      array (
      ),
      'reference' => '1a4f708e4e87f335d1b1be6148060739152f0bd5',
    ),
    'symfony/http-foundation' => 
    array (
      'pretty_version' => 'v5.4.9',
      'version' => '5.4.9.0',
      'aliases' => 
      array (
      ),
      'reference' => '6b0d0e4aca38d57605dcd11e2416994b38774522',
    ),
    'symfony/http-kernel' => 
    array (
      'pretty_version' => 'v4.4.42',
      'version' => '4.4.42.0',
      'aliases' => 
      array (
      ),
      'reference' => '04181de9459df639512dadf83d544ce12edd6776',
    ),
    'symfony/polyfill-ctype' => 
    array (
      'pretty_version' => 'v1.26.0',
      'version' => '1.26.0.0',
      'aliases' => 
      array (
      ),
      'reference' => '6fd1b9a79f6e3cf65f9e679b23af304cd9e010d4',
    ),
    'symfony/polyfill-mbstring' => 
    array (
      'pretty_version' => 'v1.26.0',
      'version' => '1.26.0.0',
      'aliases' => 
      array (
      ),
      'reference' => '9344f9cb97f3b19424af1a21a3b0e75b0a7d8d7e',
    ),
    'symfony/polyfill-php73' => 
    array (
      'pretty_version' => 'v1.26.0',
      'version' => '1.26.0.0',
      'aliases' => 
      array (
      ),
      'reference' => 'e440d35fa0286f77fb45b79a03fedbeda9307e85',
    ),
    'symfony/polyfill-php80' => 
    array (
      'pretty_version' => 'v1.26.0',
      'version' => '1.26.0.0',
      'aliases' => 
      array (
      ),
      'reference' => 'cfa0ae98841b9e461207c13ab093d76b0fa7bace',
    ),
    'symfony/polyfill-php81' => 
    array (
      'pretty_version' => 'v1.26.0',
      'version' => '1.26.0.0',
      'aliases' => 
      array (
      ),
      'reference' => '13f6d1271c663dc5ae9fb843a8f16521db7687a1',
    ),
    'symfony/routing' => 
    array (
      'pretty_version' => 'v4.4.41',
      'version' => '4.4.41.0',
      'aliases' => 
      array (
      ),
      'reference' => 'c25e38d403c00d5ddcfc514f016f1b534abdf052',
    ),
    'symfony/service-contracts' => 
    array (
      'pretty_version' => 'v2.5.1',
      'version' => '2.5.1.0',
      'aliases' => 
      array (
      ),
      'reference' => '24d9dc654b83e91aa59f9d167b131bc3b5bea24c',
    ),
    'symfony/service-implementation' => 
    array (
      'provided' => 
      array (
        0 => '1.0|2.0',
      ),
    ),
    'symfony/var-dumper' => 
    array (
      'pretty_version' => 'v5.4.9',
      'version' => '5.4.9.0',
      'aliases' => 
      array (
      ),
      'reference' => 'af52239a330fafd192c773795520dc2dd62b5657',
    ),
    'symfony/var-exporter' => 
    array (
      'pretty_version' => 'v6.1.0',
      'version' => '6.1.0.0',
      'aliases' => 
      array (
      ),
      'reference' => '33c301d3177150a52350ac893490a9289eb143dd',
    ),
    'web-token/jwt-bundle' => 
    array (
      'replaced' => 
      array (
        0 => 'v1.3.0',
      ),
    ),
    'web-token/jwt-checker' => 
    array (
      'replaced' => 
      array (
        0 => 'v1.3.0',
      ),
    ),
    'web-token/jwt-console' => 
    array (
      'replaced' => 
      array (
        0 => 'v1.3.0',
      ),
    ),
    'web-token/jwt-core' => 
    array (
      'replaced' => 
      array (
        0 => 'v1.3.0',
      ),
    ),
    'web-token/jwt-encryption' => 
    array (
      'replaced' => 
      array (
        0 => 'v1.3.0',
      ),
    ),
    'web-token/jwt-encryption-algorithm-aescbc' => 
    array (
      'replaced' => 
      array (
        0 => 'v1.3.0',
      ),
    ),
    'web-token/jwt-encryption-algorithm-aesgcm' => 
    array (
      'replaced' => 
      array (
        0 => 'v1.3.0',
      ),
    ),
    'web-token/jwt-encryption-algorithm-aesgcmkw' => 
    array (
      'replaced' => 
      array (
        0 => 'v1.3.0',
      ),
    ),
    'web-token/jwt-encryption-algorithm-aeskw' => 
    array (
      'replaced' => 
      array (
        0 => 'v1.3.0',
      ),
    ),
    'web-token/jwt-encryption-algorithm-dir' => 
    array (
      'replaced' => 
      array (
        0 => 'v1.3.0',
      ),
    ),
    'web-token/jwt-encryption-algorithm-ecdh-es' => 
    array (
      'replaced' => 
      array (
        0 => 'v1.3.0',
      ),
    ),
    'web-token/jwt-encryption-algorithm-experimental' => 
    array (
      'replaced' => 
      array (
        0 => 'v1.3.0',
      ),
    ),
    'web-token/jwt-encryption-algorithm-pbes2' => 
    array (
      'replaced' => 
      array (
        0 => 'v1.3.0',
      ),
    ),
    'web-token/jwt-encryption-algorithm-rsa' => 
    array (
      'replaced' => 
      array (
        0 => 'v1.3.0',
      ),
    ),
    'web-token/jwt-framework' => 
    array (
      'pretty_version' => 'v1.3.0',
      'version' => '1.3.0.0',
      'aliases' => 
      array (
      ),
      'reference' => '74e90e089cbfdb20abc7507f587fe58ad7009059',
    ),
    'web-token/jwt-key-mgmt' => 
    array (
      'replaced' => 
      array (
        0 => 'v1.3.0',
      ),
    ),
    'web-token/jwt-signature' => 
    array (
      'replaced' => 
      array (
        0 => 'v1.3.0',
      ),
    ),
    'web-token/jwt-signature-algorithm-ecdsa' => 
    array (
      'replaced' => 
      array (
        0 => 'v1.3.0',
      ),
    ),
    'web-token/jwt-signature-algorithm-eddsa' => 
    array (
      'replaced' => 
      array (
        0 => 'v1.3.0',
      ),
    ),
    'web-token/jwt-signature-algorithm-experimental' => 
    array (
      'replaced' => 
      array (
        0 => 'v1.3.0',
      ),
    ),
    'web-token/jwt-signature-algorithm-hmac' => 
    array (
      'replaced' => 
      array (
        0 => 'v1.3.0',
      ),
    ),
    'web-token/jwt-signature-algorithm-none' => 
    array (
      'replaced' => 
      array (
        0 => 'v1.3.0',
      ),
    ),
    'web-token/jwt-signature-algorithm-rsa' => 
    array (
      'replaced' => 
      array (
        0 => 'v1.3.0',
      ),
    ),
    'web-token/jwt-util-ecc' => 
    array (
      'replaced' => 
      array (
        0 => 'v1.3.0',
      ),
    ),
  ),
);
private static $canGetVendors;
private static $installedByVendor = array();







public static function getInstalledPackages()
{
$packages = array();
foreach (self::getInstalled() as $installed) {
$packages[] = array_keys($installed['versions']);
}


if (1 === \count($packages)) {
return $packages[0];
}

return array_keys(array_flip(\call_user_func_array('array_merge', $packages)));
}









public static function isInstalled($packageName)
{
foreach (self::getInstalled() as $installed) {
if (isset($installed['versions'][$packageName])) {
return true;
}
}

return false;
}














public static function satisfies(VersionParser $parser, $packageName, $constraint)
{
$constraint = $parser->parseConstraints($constraint);
$provided = $parser->parseConstraints(self::getVersionRanges($packageName));

return $provided->matches($constraint);
}










public static function getVersionRanges($packageName)
{
foreach (self::getInstalled() as $installed) {
if (!isset($installed['versions'][$packageName])) {
continue;
}

$ranges = array();
if (isset($installed['versions'][$packageName]['pretty_version'])) {
$ranges[] = $installed['versions'][$packageName]['pretty_version'];
}
if (array_key_exists('aliases', $installed['versions'][$packageName])) {
$ranges = array_merge($ranges, $installed['versions'][$packageName]['aliases']);
}
if (array_key_exists('replaced', $installed['versions'][$packageName])) {
$ranges = array_merge($ranges, $installed['versions'][$packageName]['replaced']);
}
if (array_key_exists('provided', $installed['versions'][$packageName])) {
$ranges = array_merge($ranges, $installed['versions'][$packageName]['provided']);
}

return implode(' || ', $ranges);
}

throw new \OutOfBoundsException('Package "' . $packageName . '" is not installed');
}





public static function getVersion($packageName)
{
foreach (self::getInstalled() as $installed) {
if (!isset($installed['versions'][$packageName])) {
continue;
}

if (!isset($installed['versions'][$packageName]['version'])) {
return null;
}

return $installed['versions'][$packageName]['version'];
}

throw new \OutOfBoundsException('Package "' . $packageName . '" is not installed');
}





public static function getPrettyVersion($packageName)
{
foreach (self::getInstalled() as $installed) {
if (!isset($installed['versions'][$packageName])) {
continue;
}

if (!isset($installed['versions'][$packageName]['pretty_version'])) {
return null;
}

return $installed['versions'][$packageName]['pretty_version'];
}

throw new \OutOfBoundsException('Package "' . $packageName . '" is not installed');
}





public static function getReference($packageName)
{
foreach (self::getInstalled() as $installed) {
if (!isset($installed['versions'][$packageName])) {
continue;
}

if (!isset($installed['versions'][$packageName]['reference'])) {
return null;
}

return $installed['versions'][$packageName]['reference'];
}

throw new \OutOfBoundsException('Package "' . $packageName . '" is not installed');
}





public static function getRootPackage()
{
$installed = self::getInstalled();

return $installed[0]['root'];
}







public static function getRawData()
{
return self::$installed;
}



















public static function reload($data)
{
self::$installed = $data;
self::$installedByVendor = array();
}




private static function getInstalled()
{
if (null === self::$canGetVendors) {
self::$canGetVendors = method_exists('Composer\Autoload\ClassLoader', 'getRegisteredLoaders');
}

$installed = array();

if (self::$canGetVendors) {

 foreach (ClassLoader::getRegisteredLoaders() as $vendorDir => $loader) {
if (isset(self::$installedByVendor[$vendorDir])) {
$installed[] = self::$installedByVendor[$vendorDir];
} elseif (is_file($vendorDir.'/composer/installed.php')) {
$installed[] = self::$installedByVendor[$vendorDir] = require $vendorDir.'/composer/installed.php';
}
}
}

$installed[] = self::$installed;

return $installed;
}
}
