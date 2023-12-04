<?php

function base32_decode($data){
    $data = strtoupper($data);
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    $decoded = '';
    $buffer = 0;
    $bufferSize = 0;

    for ($i = 0; $i < strlen($data); $i++) {
        $charValue = strpos($alphabet, $data[$i]);
        if ($charValue === false) {
            continue;
        }

        $buffer = ($buffer << 5) | $charValue;
        $bufferSize += 5;

        if ($bufferSize >= 8) {
            $decoded .= chr(($buffer >> ($bufferSize - 8)) & 0xFF);
            $bufferSize -= 8;
        }
    }

    return $decoded;
}

function generateTOTP($secret, $time, $digits){
    $timestamp = floor($time / 30); // Fenêtre de 30 secondes pour TOTP
    $secret = base32_decode($secret);

    $time = pack('N*', 0, $timestamp); // Convertir le temps en bytes

    // Calculer l'HMAC-SHA1
    $hash = hash_hmac('sha1', $time, $secret, true);

    // Obtenir l'index du dernier octet dans lequel se trouve le dernier bit de l'octet
    $offset = ord(substr($hash, -1)) & 0x0F;

    // Extraire 4 octets à partir de l'offset
    $otpHash = substr($hash, $offset, 4);

    // Convertir les octets en un entier non signé (big-endian)
    $otpInt = unpack('N', $otpHash)[1];

    // Ne conserver que les 31 derniers bits
    $otpInt &= 0x7FFFFFFF;

    // Obtenir les derniers $digits chiffres de l'OTP
    $otp = str_pad($otpInt % (10 ** $digits), $digits, '0', STR_PAD_LEFT);

    return $otp;
}


// Obtenir la clef secrete passee en argument.
$secretKey = $argv[1];

// Longeur du pass OTP a retourner
$digits = 6;

// Obtenir le temps UNIX actuel
$time = time();

// Generation de l'OTP
$otp = generateTOTP($secretKey, $time, $digits);

echo "OTP actuel: $otp\n";
?>
