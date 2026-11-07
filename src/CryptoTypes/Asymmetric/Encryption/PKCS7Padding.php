<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\Asymmetric\Encryption;

use LogicException;
use function mb_strlen;
use function mb_substr;
use function ord;

/**
 * PKCS #7 padding as RFC 8018 sect. 6.1.1 and RFC 1423 sect. 1.1 apply it to a CBC cipher.
 *
 * `Crypto` leaves the padding to its caller.
 *
 * @internal
 */
final class PKCS7Padding
{
    public static function add(string $data, int $blockSize): string
    {
        if ($blockSize < 1 || $blockSize > 255) {
            throw new LogicException('Invalid block size.');
        }
        $pad = $blockSize - mb_strlen($data, '8bit') % $blockSize;
        return $data . str_repeat(pack('C', $pad), $pad);
    }

    /**
     * Remove the padding, or return null if there is no valid padding.
     *
     * Every byte of the last block is inspected whatever the padding length turns out to be, and the checks are
     * folded together with arithmetic rather than branches, so the time taken does not tell how much of the padding
     * was right. The length check comes first and may return early, since the length of a ciphertext is no secret.
     */
    public static function remove(string $data, int $blockSize): ?string
    {
        $length = mb_strlen($data, '8bit');
        if ($blockSize < 1 || $blockSize > 255 || $length === 0 || $length % $blockSize !== 0) {
            return null;
        }
        $pad = ord($data[$length - 1]);
        // a padding length of 0 or above the block size: either difference turns negative, setting bit 31
        $bad = (($pad - 1) | ($blockSize - $pad)) >> 31 & 1;
        for ($i = 1; $i <= $blockSize; ++$i) {
            // 1 for the bytes that are part of the padding, that is when $i <= $pad
            $inPadding = ($i - $pad - 1) >> 31 & 1;
            $bad |= $inPadding * (ord($data[$length - $i]) ^ $pad);
        }
        if ($bad !== 0) {
            return null;
        }
        return mb_substr($data, 0, $length - $pad, '8bit');
    }
}
