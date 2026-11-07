<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\Asymmetric\Encryption;

use function mb_strlen;
use function mb_substr;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\CryptoBridge\Crypto;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Cipher\AES128CBCAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Cipher\AES192CBCAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Cipher\AES256CBCAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Cipher\BlockCipherAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Cipher\DESCBCAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Cipher\DESEDE3CBCAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\Exception\InvalidPasswordException;
use function sprintf;
use function strtoupper;
use Throwable;
use UnexpectedValueException;

/**
 * Decryption of the traditional OpenSSL encrypted PEM format.
 *
 * This is what `openssl rsa -aes256 -traditional` and `openssl ec -aes256` write: the PKCS #1 or SEC 1 key itself,
 * encrypted as RFC 1421 describes, with a `Proc-Type: 4,ENCRYPTED` and a `DEK-Info: <cipher>,<hex IV>` header. The key
 * is OpenSSL's `EVP_BytesToKey()` with MD5, a single iteration and the first 8 bytes of the IV as the salt, which is
 * weak by any current measure: prefer PKCS #8, `ENCRYPTED PRIVATE KEY`, which this library also writes.
 *
 * @see https://tools.ietf.org/html/rfc1421#section-4.6.1.3
 * @see https://tools.ietf.org/html/rfc1423#section-1.1
 */
final class LegacyPEMEncryption
{
    /**
     * Decrypt a PEM with a `Proc-Type: 4,ENCRYPTED` header.
     *
     * @return PEM A PEM of the same type with the DER of the decrypted key and no headers
     */
    public static function decrypt(PEM $pem, string $password, ?Crypto $crypto = null): PEM
    {
        if (! $pem->isEncrypted()) {
            throw new UnexpectedValueException('PEM is not encrypted.');
        }
        $dekInfo = $pem->header(PEM::HEADER_DEK_INFO);
        if ($dekInfo === null || preg_match('/\A([A-Za-z0-9-]+),([0-9A-Fa-f]+)\z/', $dekInfo, $match) !== 1) {
            throw new UnexpectedValueException('Missing or malformed DEK-Info header.');
        }
        $iv = (string) hex2bin(mb_strlen($match[2], '8bit') % 2 === 0 ? $match[2] : '');
        $cipher = self::cipher($match[1], $iv);
        $data = $pem->data();
        $length = mb_strlen($data, '8bit');
        if ($length === 0 || $length % $cipher->blockSize() !== 0) {
            throw new UnexpectedValueException(sprintf(
                'Encrypted data length %d is not a positive multiple of the %s block size.',
                $length,
                $cipher->name()
            ));
        }
        $key = self::bytesToKey($password, mb_substr($iv, 0, 8, '8bit'), $cipher->keySize());
        $crypto ??= Crypto::getDefault();
        $plaintext = PKCS7Padding::remove($crypto->decrypt($data, $key, $cipher), $cipher->blockSize());
        if ($plaintext === null || ! self::isDERSequence($plaintext)) {
            throw new InvalidPasswordException('Invalid password or corrupted data.');
        }
        return PEM::create($pem->type(), $plaintext);
    }

    /**
     * OpenSSL's `EVP_BytesToKey()` with MD5 and an iteration count of 1, which is what `PEM_do_header()` uses.
     *
     * D_1 = MD5(password || salt), D_i = MD5(D_(i-1) || password || salt), key = D_1 || D_2 || ... truncated.
     *
     * @internal
     */
    public static function bytesToKey(string $password, string $salt, int $keySize): string
    {
        $key = '';
        $block = '';
        while (mb_strlen($key, '8bit') < $keySize) {
            $block = md5($block . $password . $salt, true);
            $key .= $block;
        }
        return mb_substr($key, 0, $keySize, '8bit');
    }

    private static function cipher(string $name, string $iv): BlockCipherAlgorithmIdentifier
    {
        $name = strtoupper($name);
        // the IV size is checked by the algorithm identifier, but its error says nothing about where it came from
        $ivSize = $name === 'DES-CBC' || $name === 'DES-EDE3-CBC' ? 8 : 16;
        if (mb_strlen($iv, '8bit') !== $ivSize) {
            throw new UnexpectedValueException('Invalid IV in DEK-Info header.');
        }
        return match ($name) {
            'AES-128-CBC' => AES128CBCAlgorithmIdentifier::create($iv),
            'AES-192-CBC' => AES192CBCAlgorithmIdentifier::create($iv),
            'AES-256-CBC' => AES256CBCAlgorithmIdentifier::create($iv),
            'DES-EDE3-CBC' => DESEDE3CBCAlgorithmIdentifier::create($iv),
            'DES-CBC' => DESCBCAlgorithmIdentifier::create($iv),
            default => throw new UnexpectedValueException(sprintf('DEK-Info cipher %s is not supported.', $name)),
        };
    }

    /**
     * Whether the data is a single DER encoded SEQUENCE and nothing else, as every traditional key is.
     *
     * Padding that happens to look valid is not rare enough under a wrong key, about one in 256, to stand on its own.
     */
    private static function isDERSequence(string $data): bool
    {
        try {
            $offset = 0;
            $element = Element::fromDER($data, $offset);
            return $element instanceof Sequence && $offset === mb_strlen($data, '8bit');
        } catch (Throwable) {
            return false;
        }
    }
}
