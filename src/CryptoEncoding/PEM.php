<?php

declare(strict_types=1);

namespace Sop\CryptoEncoding;

use RuntimeException;
use UnexpectedValueException;

/**
 * Implements PEM file encoding and decoding.
 *
 * @see https://tools.ietf.org/html/rfc7468
 */
class PEM
{
    // well-known PEM types
    public const TYPE_CERTIFICATE = 'CERTIFICATE';

    public const TYPE_CRL = 'X509 CRL';

    public const TYPE_CERTIFICATE_REQUEST = 'CERTIFICATE REQUEST';

    public const TYPE_ATTRIBUTE_CERTIFICATE = 'ATTRIBUTE CERTIFICATE';

    public const TYPE_PRIVATE_KEY = 'PRIVATE KEY';

    public const TYPE_PUBLIC_KEY = 'PUBLIC KEY';

    public const TYPE_ENCRYPTED_PRIVATE_KEY = 'ENCRYPTED PRIVATE KEY';

    public const TYPE_RSA_PRIVATE_KEY = 'RSA PRIVATE KEY';

    public const TYPE_RSA_PUBLIC_KEY = 'RSA PUBLIC KEY';

    public const TYPE_EC_PRIVATE_KEY = 'EC PRIVATE KEY';

    public const TYPE_PKCS7 = 'PKCS7';

    public const TYPE_CMS = 'CMS';

    /**
     * Regular expression to match PEM block.
     *
     * @var string
     */
    public const PEM_REGEX = '/' .
        /* line start */ '(?:^|[\r\n])' .
        /* header */     '-----BEGIN (.+?)-----[\r\n]+' .
        /* payload */    '(.+?)' .
        /* trailer */    '[\r\n]+-----END \\1-----' .
    '/ms';

    /**
     * Content type.
     *
     * @var string
     */
    protected $_type;

    /**
     * Payload.
     *
     * @var string
     */
    protected $_data;

    /**
     * Constructor.
     *
     * @param string $type Content type
     * @param string $data Payload
     */
    public function __construct(string $type, string $data)
    {
        $this->_type = $type;
        $this->_data = $data;
    }

    public function __toString(): string
    {
        return $this->string();
    }

    /**
     * Initialize from a PEM-formatted string.
     */
    public static function fromString(string $str): self
    {
        if (! preg_match(self::PEM_REGEX, $str, $match)) {
            throw new UnexpectedValueException('Not a PEM formatted string.');
        }
        $payload = preg_replace('/\s+/', '', $match[2]);
        $data = base64_decode($payload, true);
        if ($data === false) {
            throw new UnexpectedValueException('Failed to decode PEM data.');
        }
        return new self($match[1], $data);
    }

    /**
     * Initialize from a file.
     *
     * @param string $filename Path to file
     */
    public static function fromFile(string $filename): self
    {
        if (! is_readable($filename) ||
            false === ($str = file_get_contents($filename))) {
            throw new RuntimeException("Failed to read {$filename}.");
        }
        return self::fromString($str);
    }

    /**
     * Get content type.
     */
    public function type(): string
    {
        return $this->_type;
    }

    public function data(): string
    {
        return $this->_data;
    }

    /**
     * Encode to PEM string.
     */
    public function string(): string
    {
        return "-----BEGIN {$this->_type}-----\n" .
            trim(chunk_split(base64_encode($this->_data), 64, "\n")) . "\n" .
            "-----END {$this->_type}-----";
    }
}
