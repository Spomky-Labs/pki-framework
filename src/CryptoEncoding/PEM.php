<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoEncoding;

use function array_key_exists;
use function count;
use function is_string;
use function mb_strlen;
use function mb_substr;
use function preg_last_error_msg;
use const PREG_SPLIT_NO_EMPTY;
use RuntimeException;
use Stringable;
use UnexpectedValueException;

/**
 * Implements PEM file encoding and decoding.
 *
 * @see https://tools.ietf.org/html/rfc7468
 */
final class PEM implements Stringable
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
     * The label and the payload are both constrained to the characters RFC 7468 allows them. Written with two lazy
     * `.+?` under the `s` modifier and no anchoring, the engine tried every `-----` for the label and, for each one,
     * expanded the payload across the whole remainder: repeated BEGIN lines with no matching END drove cubic
     * backtracking, and a few kilobytes of them cost more than parsing thousands of real certificates.
     *
     * The second group is the encapsulated text, the third the optional RFC 1421 header block that precedes it,
     * blank line included, so that group 2 of a block without headers is exactly the base64 payload it always was.
     * Header lines are `Name: value`, with a name of letters, digits and dashes, a value of printable ASCII, and the
     * block must end in an empty line. Every part of it is possessive or atomic: a header name cannot contain a
     * colon, a value cannot contain a line break and a base64 line can contain neither a colon nor a dash, so there
     * is never more than one way to read a line and nothing to backtrack into.
     *
     * @var string
     */
    public const PEM_REGEX = '/' .
        /* line start */
        '(?:^|[\r\n])' .
        /* header, a label on a single line */
        '-----BEGIN ([A-Za-z0-9][A-Za-z0-9 ]*)-----[\r\n]+' .
        /* encapsulated text */
        '(' .
        /* optional RFC 1421 headers, terminated by an empty line */
        '(' . self::HEADER_BLOCK_REGEX . ')?' .
        /* payload, base64 and the whitespace that breaks it into lines */
        '[A-Za-z0-9+\/=\r\n\t ]+?)' .
        /* trailer */
        '[\r\n]+-----END \\1-----' .
        '/m';

    /**
     * Header field in an RFC 1421 encapsulated header, which `Proc-Type` and `DEK-Info` of a traditional OpenSSL
     * encrypted key are.
     *
     * Folded continuation lines are not supported, as neither OpenSSL writes nor reads them.
     *
     * @internal
     *
     * @var string
     */
    private const HEADER_LINE_REGEX = '[A-Za-z0-9][A-Za-z0-9-]*+:[\t\x20-\x7E]*+(?:\r\n?|\n)';

    /**
     * @internal
     *
     * @var string
     */
    private const HEADER_BLOCK_REGEX = '(?>(?:' . self::HEADER_LINE_REGEX . ')++)(?:\r\n?|\n)';

    /**
     * Header that marks an RFC 1421 encrypted block.
     *
     * @var string
     */
    public const HEADER_PROC_TYPE = 'Proc-Type';

    /**
     * Header that names the cipher and the IV of an RFC 1421 encrypted block.
     *
     * @var string
     */
    public const HEADER_DEK_INFO = 'DEK-Info';

    /**
     * @param string $type Content type
     * @param string $data Payload
     * @param array<string, string> $headers RFC 1421 headers, in order
     */
    private function __construct(
        private readonly string $type,
        private readonly string $data,
        private readonly array $headers
    ) {
    }

    public function __toString(): string
    {
        return $this->string();
    }

    /**
     * @param array<string, string> $headers RFC 1421 headers, eg. `Proc-Type` and `DEK-Info` of a traditional
     * OpenSSL encrypted key, in the order they are to be written
     */
    public static function create(string $_type, string $_data, array $headers = []): self
    {
        foreach ($headers as $name => $value) {
            // a header is written verbatim, so a line break in either part would forge another header or the payload
            if (preg_match('/\A[A-Za-z0-9][A-Za-z0-9-]*\z/', (string) $name) !== 1) {
                throw new UnexpectedValueException('Invalid PEM header name.');
            }
            if (preg_match('/\A[\t\x20-\x7E]*\z/', $value) !== 1) {
                throw new UnexpectedValueException('Invalid PEM header value.');
            }
        }
        return new self($_type, $_data, $headers);
    }

    /**
     * Initialize from a PEM-formatted string.
     */
    public static function fromString(string $str): self
    {
        $result = preg_match(self::PEM_REGEX, $str, $match);
        if ($result === false) {
            // a matcher that gave up says nothing about the input, so it must not be reported as malformed
            throw new RuntimeException('Failed to match a PEM block: ' . preg_last_error_msg() . '.');
        }
        if ($result !== 1) {
            throw new UnexpectedValueException('Not a PEM formatted string.');
        }
        return self::fromMatch($match);
    }

    /**
     * Initialize from a match of `PEM_REGEX`.
     *
     * @internal
     *
     * @param array<int|string, string> $match
     */
    public static function fromMatch(array $match): self
    {
        $headerBlock = $match[3] ?? '';
        $payload = preg_replace('/\s+/', '', mb_substr($match[2], mb_strlen($headerBlock, '8bit'), null, '8bit'));
        if (! is_string($payload)) {
            throw new UnexpectedValueException('Failed to decode PEM data.');
        }
        // base64_decode() is strict about the alphabet but not about padding, so a blob that OpenSSL refuses
        // would otherwise be accepted here (RFC 7468 sect. 3 requires the padded alphabet of RFC 4648)
        if (mb_strlen($payload, '8bit') % 4 !== 0) {
            throw new UnexpectedValueException('Failed to decode PEM data.');
        }
        $data = base64_decode($payload, true);
        if ($data === false) {
            throw new UnexpectedValueException('Failed to decode PEM data.');
        }
        return self::create($match[1], $data, self::parseHeaders($headerBlock));
    }

    /**
     * Initialize from a file.
     *
     * @param string $filename Path to file
     */
    public static function fromFile(string $filename): self
    {
        if (! is_readable($filename)) {
            throw new RuntimeException("Failed to read {$filename}.");
        }
        $str = file_get_contents($filename);
        if ($str === false) {
            throw new RuntimeException("Failed to read {$filename}.");
        }
        return self::fromString($str);
    }

    /**
     * Get content type.
     */
    public function type(): string
    {
        return $this->type;
    }

    public function data(): string
    {
        return $this->data;
    }

    /**
     * Get the RFC 1421 headers, keyed by name in the order they appear.
     *
     * @return array<string, string>
     */
    public function headers(): array
    {
        return $this->headers;
    }

    /**
     * Whether the block carries RFC 1421 headers.
     */
    public function hasHeaders(): bool
    {
        return count($this->headers) !== 0;
    }

    /**
     * Get the value of a header, or null if it is absent.
     *
     * Header names are compared case sensitively, as OpenSSL does.
     */
    public function header(string $name): ?string
    {
        return $this->headers[$name] ?? null;
    }

    /**
     * Whether the payload is encrypted as RFC 1421 describes, that is with a `Proc-Type: 4,ENCRYPTED` header.
     *
     * This is the traditional OpenSSL format of an encrypted RSA or EC private key. A PKCS #8 encrypted key
     * carries no headers and is told apart by its type, `ENCRYPTED PRIVATE KEY`.
     */
    public function isEncrypted(): bool
    {
        $procType = $this->header(self::HEADER_PROC_TYPE);
        return $procType !== null && preg_match('/\A4[\t ]*,[\t ]*ENCRYPTED\z/', $procType) === 1;
    }

    /**
     * Encode to PEM string.
     */
    public function string(): string
    {
        $headers = '';
        foreach ($this->headers as $name => $value) {
            $headers .= "{$name}: {$value}\n";
        }
        if ($headers !== '') {
            $headers .= "\n";
        }
        return "-----BEGIN {$this->type}-----\n" . $headers .
            trim(chunk_split(base64_encode($this->data), 64, "\n")) . "\n" .
            "-----END {$this->type}-----";
    }

    /**
     * Parse the header block matched by `HEADER_BLOCK_REGEX`.
     *
     * @return array<string, string>
     */
    private static function parseHeaders(string $block): array
    {
        $headers = [];
        $lines = preg_split('/\r\n?|\n/', $block, -1, PREG_SPLIT_NO_EMPTY);
        foreach ($lines === false ? [] : $lines as $line) {
            [$name, $value] = explode(':', $line, 2);
            if (array_key_exists($name, $headers)) {
                throw new UnexpectedValueException("Duplicate PEM header {$name}.");
            }
            $headers[$name] = trim($value, " \t");
        }
        return $headers;
    }
}
