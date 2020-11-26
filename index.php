<?php

require __DIR__ . '/vendor/autoload.php';

/**
 * An array to pass to "encrypt" and "decrypt" methods.
 */
$params = [
  'driver' => 'openssl',
  'cipher' => 'aes-128',
  'mode' => 'cbc',
  'key' => 'key_string',
  'base64' => TRUE,
  'hmac_digest' => 'sha512',
  'hmac_key' => 'hmac_key_string',
];

// Create Cipher class object.
$cipher = new Encryption\Cipher();

// A dummy Credit card number to encrypt.
$creditCardNumber = '9568-5656-8124-6367';
$encrypted = $cipher->encrypt($creditCardNumber, $params);

echo $encrypted;

echo '<br/>';

// Decrypt the Credit card number which was encrypted initially.
echo $cipher->decrypt($encrypted, $params);
