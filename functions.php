<?php

# Copyright 2024, Ludwig V. <https://github.com/ludwig-v>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License at <http://www.gnu.org/licenses/> for
# more details.

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# mgf1 and emsa_pss_encode adapted from the work of Jim Wigginton <terrafrost@php.net>
# Feel free to adjust hashType (along with hashLen) and saltLen to your needs

function rsa_mgf1($mgfSeed, $maskLen) {
    $hashType = 'sha256';
    $hashLen = 32;

    $t = '';
    $count = ceil($maskLen / $hashLen);
    for ($i = 0; $i < $count; $i++) {
        $c = pack('N', $i);
        $t .= hash($hashType, $mgfSeed . $c, true);
    }

    return substr($t, 0, $maskLen);
}

function rsa_emsa_pss_encode($m, $emBits, $saltLen = 32) {
    $hashType = 'sha256';
    $hashLen = 32;

    $emLen = $emBits + 1 >> 3;

    $mHash = hash($hashType, $m, true);
    if ($emLen < $hashLen + $saltLen + 2) {
        return false;
    }

    $salt = openssl_random_pseudo_bytes($saltLen);
    $m2 = "\0\0\0\0\0\0\0\0" . $mHash . $salt;
    $h = hash($hashType, $m2, true);
    $ps = str_repeat(chr(0), $emLen - $saltLen - $hashLen - 2);
    $db = $ps.chr(1).$salt;
    $dbMask = rsa_mgf1($h, $emLen - $hashLen - 1);
    $maskedDB = $db ^ $dbMask;
    $maskedDB[0] = ~chr(0xff << ($emBits & 7)) & $maskedDB[0];
    $em = $maskedDB . $h . chr(0xbc);

    return $em;
}

function rsassa_pss_sign($key, $plainText, $rawOutput = false) {
    $privatePEMKey = openssl_pkey_get_private($key);
	$privateKeyDetails = openssl_pkey_get_details($privatePEMKey);

    $encryptedData = rsa_emsa_pss_encode($plainText, $privateKeyDetails['bits'] - 1);
	if ($encryptedData) {
		$signature = '';
		$encryptionOk = openssl_private_encrypt($encryptedData, $signature, $privatePEMKey, OPENSSL_NO_PADDING);
		if ($encryptionOk === false) {
			return false;
		}

		if ($rawOutput) {
			return $signature;
		} else {
			return base64_encode($signature);
		}
	}

	return false;
}

# Usage example
$privateKey = file_get_contents('privatekey.pem');
$generatedSignature = rsassa_pss_sign($privateKey, 'This is a test');
echo $generatedSignature;

?>