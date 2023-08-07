<?php

namespace Ledc\GoogleCode;

use Exception;

/**
 * 谷歌验证器
 */
class GoogleAuthenticator
{
    /**
     * 验证码长度
     * @var int
     */
    protected int $_codeLength = 6;

    /**
     * 创建新的secret密钥
     * @param int $secretLength 长度
     * @return string
     * @throws Exception
     */
    public function createSecret(int $secretLength = 16): string
    {
        $validChars = $this->_getBase32LookupTable();

        // Valid secret lengths are 80 to 640 bits
        if ($secretLength < 16 || $secretLength > 128) {
            throw new Exception('Bad secret length');
        }
        if (($secretLength & ($secretLength - 1)) !== 0) {
            throw new Exception('This secret key is not compatible with Google Authenticator.');
        }
        $secret = '';
        for ($i = 0; $i < $secretLength; ++$i) {
            if (function_exists('random_int')) {
                $secret .= $validChars[random_int(0, 31)];
            } else {
                $secret .= $validChars[mt_rand(0, 31)];
            }
        }

        return $secret;
    }

    /**
     * Get array with all 32 characters for decoding from/encoding to base32.
     * @return array
     */
    protected function _getBase32LookupTable(): array
    {
        return [
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', //  7
            'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', // 15
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', // 23
            'Y', 'Z', '2', '3', '4', '5', '6', '7', // 31
            '=',  // padding char
        ];
    }

    /**
     * 从谷歌charts获取二维码图片的url
     * @param string $name
     * @param string $secret
     * @param string|null $title
     * @param array $params
     * @return string
     */
    public function getQRCodeGoogleUrl(string $name, string $secret, string $title = null, array $params = array()): string
    {
        $width = !empty($params['width']) && (int)$params['width'] > 0 ? (int)$params['width'] : 200;
        $height = !empty($params['height']) && (int)$params['height'] > 0 ? (int)$params['height'] : 200;
        $level = !empty($params['level']) && in_array($params['level'], array('L', 'M', 'Q', 'H')) ? $params['level'] : 'M';

        $urlencoded = urlencode('otpauth://totp/' . $name . '?secret=' . $secret);
        if (isset($title)) {
            $urlencoded .= urlencode('&issuer=' . urlencode($title));
        }

        return 'https://chart.googleapis.com/chart?chs=' . $width . 'x' . $height . '&chld=' . $level . '|0&cht=qr&chl=' . $urlencoded;
    }

    /**
     * 校验验证码是否正确
     * Check if the code is correct. This will accept codes starting from $discrepancy*30sec ago to $discrepancy*30sec from now.
     *
     * @param string $secret
     * @param string $code
     * @param int $discrepancy This is the allowed time drift in 30 second units (8 means 4 minutes before or after)
     * @param int|null $currentTimeSlice time slice if we want use other that time()
     *
     * @return bool
     */
    public function verifyCode(string $secret, string $code, int $discrepancy = 1, int $currentTimeSlice = null): bool
    {
        if ($currentTimeSlice === null) {
            $currentTimeSlice = floor(time() / 30);
        }

        if (strlen($code) !== $this->_codeLength) {
            return false;
        }

        for ($i = -$discrepancy; $i <= $discrepancy; ++$i) {
            $calculatedCode = $this->getCode($secret, $currentTimeSlice + $i);
            if ($this->timingSafeEquals($calculatedCode, $code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 生成验证码
     * - 根据密钥和时间戳生成
     * @param string $secret
     * @param int|null $timeSlice
     * @return string
     */
    public function getCode(string $secret, int $timeSlice = null): string
    {
        if ($timeSlice === null) {
            $timeSlice = floor(time() / 30);
        }
        $secretKey = $this->_base32Decode($secret);

        // Pack time into binary string
        $time = chr(0) . chr(0) . chr(0) . chr(0) . pack('N*', $timeSlice);
        // Hash it with users secret key
        $hm = hash_hmac('SHA1', $time, $secretKey, true);
        // Use last nipple of result as index/offset
        $offset = ord(substr($hm, -1)) & 0x0F;
        // grab 4 bytes of the result
        $hashPart = substr($hm, $offset, 4);

        // Unpak binary value
        $value = unpack('N', $hashPart);
        $value = $value[1];
        // Only 32 bits
        $value = $value & 0x7FFFFFFF;

        return str_pad(substr((string)$value, -$this->_codeLength), $this->_codeLength, '0', STR_PAD_LEFT);
    }

    /**
     * Helper class to decode base32.
     *
     * @param string $secret
     *
     * @return bool|string
     */
    protected function _base32Decode(string $secret): bool|string
    {
        if (empty($secret)) {
            return '';
        }

        $base32chars = $this->_getBase32LookupTable();
        $base32charsFlipped = array_flip($base32chars);

        $paddingCharCount = substr_count($secret, $base32chars[32]);
        $allowedValues = array(6, 4, 3, 1, 0);
        if (!in_array($paddingCharCount, $allowedValues)) {
            return false;
        }
        for ($i = 0; $i < 4; ++$i) {
            if ($paddingCharCount == $allowedValues[$i] &&
                substr($secret, -($allowedValues[$i])) != str_repeat($base32chars[32], $allowedValues[$i])) {
                return false;
            }
        }
        $secret = str_replace('=', '', $secret);
        $secret = str_split($secret);
        $binaryString = '';
        for ($i = 0; $i < count($secret); $i = $i + 8) {
            $x = '';
            if (!in_array($secret[$i], $base32chars)) {
                return false;
            }
            for ($j = 0; $j < 8; ++$j) {
                $x .= str_pad(base_convert(@$base32charsFlipped[@$secret[$i + $j]], 10, 2), 5, '0', STR_PAD_LEFT);
            }
            $eightBits = str_split($x, 8);
            for ($z = 0; $z < count($eightBits); ++$z) {
                $binaryString .= (($y = chr(base_convert($eightBits[$z], 2, 10))) || ord($y) == 48) ? $y : '';
            }
        }

        return $binaryString;
    }

    /**
     * A timing safe equals comparison
     * more info here: http://blog.ircmaxell.com/2014/11/its-all-about-time.html.
     *
     * @param string $safeString The internal (safe) value to be checked
     * @param string $userString The user submitted (unsafe) value
     *
     * @return bool True if the two strings are identical
     */
    private function timingSafeEquals(string $safeString, string $userString): bool
    {
        if (function_exists('hash_equals')) {
            return hash_equals($safeString, $userString);
        }
        $safeLen = strlen($safeString);
        $userLen = strlen($userString);

        if ($userLen !== $safeLen) {
            return false;
        }

        $result = 0;
        for ($i = 0; $i < $userLen; ++$i) {
            $result |= (ord($safeString[$i]) ^ ord($userString[$i]));
        }

        // They are only identical strings if $result is exactly 0...
        return $result === 0;
    }

    /**
     * Set the code length, should be >=6.
     * @param int $length
     * @return GoogleAuthenticator
     */
    public function setCodeLength(int $length): GoogleAuthenticator
    {
        $this->_codeLength = $length;
        return $this;
    }
}