<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\ASN1\Type\Primitive;

use function chr;
use function count;
use GMP;
use const GMP_BIG_ENDIAN;
use const GMP_MSW_FIRST;
use function in_array;
use const INF;
use LogicException;
use function mb_strlen;
use function ord;
use RangeException;
use SpomkyLabs\Pki\ASN1\Component\Identifier;
use SpomkyLabs\Pki\ASN1\Component\Length;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Feature\ElementBase;
use SpomkyLabs\Pki\ASN1\Type\PrimitiveType;
use SpomkyLabs\Pki\ASN1\Type\UniversalClass;
use SpomkyLabs\Pki\ASN1\Util\BigInt;
use Stringable;
use UnexpectedValueException;

/**
 * Implements *REAL* type.
 */
final class Real extends Element implements Stringable
{
    use UniversalClass;
    use PrimitiveType;

    /**
     * Regex pattern to parse NR1 form number.
     *
     * @var string
     */
    final public const NR1_REGEX = '/^\s*' .
        '(?<s>[+\-])?' .    // sign
        '(?<i>\d+)' .       // integer
    '$/';

    /**
     * Regex pattern to parse NR2 form number.
     *
     * @var string
     */
    final public const NR2_REGEX = '/^\s*' .
        '(?<s>[+\-])?' .                            // sign
        '(?<d>(?:\d+[\.,]\d*)|(?:\d*[\.,]\d+))' .   // decimal number
    '$/';

    /**
     * Regex pattern to parse NR3 form number.
     *
     * @var string
     */
    final public const NR3_REGEX = '/^\s*' .
        '(?<ms>[+\-])?' .                           // mantissa sign
        '(?<m>(?:\d+[\.,]\d*)|(?:\d*[\.,]\d+))' .   // mantissa
        '[Ee](?<es>[+\-])?' .                       // exponent sign
        '(?<e>\d+)' .                               // exponent
    '$/';

    /**
     * Regex pattern to parse PHP exponent number format.
     *
     * @see http://php.net/manual/en/language.types.float.php
     *
     * @var string
     */
    final public const PHP_EXPONENT_DNUM = '/^' .
        '(?<ms>[+\-])?' .               // sign
        '(?<m>' .
            '\d+' .                     // LNUM
            '|' .
            '(?:\d*\.\d+|\d+\.\d*)' .   // DNUM
        ')[eE]' .
        '(?<es>[+\-])?(?<e>\d+)' .      // exponent
    '$/';

    /**
     * Exponent when value is positive or negative infinite.
     *
     * @var int
     */
    final public const INF_EXPONENT = 2047;

    /**
     * Exponent bias for IEEE 754 double precision float.
     *
     * @var int
     */
    final public const EXP_BIAS = -1023;

    /**
     * Signed integer mantissa.
     */
    private readonly BigInt $_mantissa;

    /**
     * Signed integer exponent.
     */
    private readonly BigInt $_exponent;

    /**
     * Abstract value base.
     *
     * Must be 2 or 10.
     */
    private readonly int $_base;

    /**
     * Whether to encode strictly in DER.
     */
    private bool $_strictDer;

    /**
     * Number as a native float.
     *
     * @internal Lazily initialized
     */
    private ?float $_float = null;

    /**
     * Constructor.
     *
     * @param GMP|int|string $mantissa Integer mantissa
     * @param GMP|int|string $exponent Integer exponent
     * @param int             $base     Base, 2 or 10
     */
    public function __construct($mantissa, $exponent, int $base = 10)
    {
        if ($base !== 10 && $base !== 2) {
            throw new UnexpectedValueException('Base must be 2 or 10.');
        }
        $this->_typeTag = self::TYPE_REAL;
        $this->_strictDer = true;
        $this->_mantissa = new BigInt($mantissa);
        $this->_exponent = new BigInt($exponent);
        $this->_base = $base;
    }

    public function __toString(): string
    {
        return sprintf('%g', $this->floatVal());
    }

    /**
     * Create base 2 real number from float.
     */
    public static function fromFloat(float $number): self
    {
        if (is_infinite($number)) {
            return self::_fromInfinite($number);
        }
        if (is_nan($number)) {
            throw new UnexpectedValueException('NaN values not supported.');
        }
        [$m, $e] = self::_parse754Double(pack('E', $number));
        return new self($m, $e, 2);
    }

    /**
     * Create base 10 real number from string.
     *
     * @param string $number Real number in base-10 textual form
     */
    public static function fromString(string $number): self
    {
        [$m, $e] = self::_parseString($number);
        return new self($m, $e, 10);
    }

    /**
     * Get self with strict DER flag set or unset.
     *
     * @param bool $strict whether to encode strictly in DER
     */
    public function withStrictDER(bool $strict): self
    {
        $obj = clone $this;
        $obj->_strictDer = $strict;
        return $obj;
    }

    /**
     * Get the mantissa.
     */
    public function mantissa(): BigInt
    {
        return $this->_mantissa;
    }

    /**
     * Get the exponent.
     */
    public function exponent(): BigInt
    {
        return $this->_exponent;
    }

    /**
     * Get the base.
     */
    public function base(): int
    {
        return $this->_base;
    }

    /**
     * Get number as a float.
     */
    public function floatVal(): float
    {
        if (! isset($this->_float)) {
            $m = $this->_mantissa->intVal();
            $e = $this->_exponent->intVal();
            $this->_float = (float) ($m * $this->_base ** $e);
        }
        return $this->_float;
    }

    /**
     * Get number as a NR3 form string conforming to DER rules.
     */
    public function nr3Val(): string
    {
        // convert to base 10
        if ($this->_base === 2) {
            [$m, $e] = self::_parseString(sprintf('%15E', $this->floatVal()));
        } else {
            $m = $this->_mantissa->gmpObj();
            $e = $this->_exponent->gmpObj();
        }
        $zero = gmp_init(0);
        $ten = gmp_init(10, 10);

        // shift trailing zeroes from the mantissa to the exponent
        // (X.690 07-2002, section 11.3.2.4)
        while (gmp_cmp($m, $zero) !== 0 && gmp_cmp(gmp_mod($m, $ten), $zero) === 0) {
            $m = gmp_div($m, $ten);
            ++$e;
        }
        // if exponent is zero, it must be prefixed with a "+" sign
        // (X.690 07-2002, section 11.3.2.6)
        if (gmp_cmp($e, 0) === 0) {
            $es = '+';
        } else {
            $es = $e < 0 ? '-' : '';
        }
        return sprintf('%s.E%s%s', gmp_strval($m), $es, gmp_strval(gmp_abs($e)));
    }

    protected function _encodedContentDER(): string
    {
        $infExponent = gmp_init(self::INF_EXPONENT, 10);
        if (gmp_cmp($this->_exponent->gmpObj(), $infExponent) === 0) {
            return $this->_encodeSpecial();
        }
        // if the real value is the value zero, there shall be no contents
        // octets in the encoding. (X.690 07-2002, section 8.5.2)
        if ($this->_mantissa->gmpObj() === 0) {
            return '';
        }
        if ($this->_base === 10) {
            return $this->_encodeDecimal();
        }
        return $this->_encodeBinary();
    }

    /**
     * Encode in binary format.
     */
    protected function _encodeBinary(): string
    {
        [$base, $sign, $m, $e] = $this->_prepareBinaryEncoding();
        $zero = gmp_init(0, 10);
        $byte = 0x80;
        if ($sign < 0) {
            $byte |= 0x40;
        }
        // normalization: mantissa must be 0 or odd
        if ($base === 2) {
            // while last bit is zero
            while ($m > 0 && gmp_cmp($m & 0x01, $zero) === 0) {
                $m >>= 1;
                ++$e;
            }
        } elseif ($base === 8) {
            $byte |= 0x10;
            // while last 3 bits are zero
            while ($m > 0 && gmp_cmp($m & 0x07, $zero) === 0) {
                $m >>= 3;
                ++$e;
            }
        } else { // base === 16
            $byte |= 0x20;
            // while last 4 bits are zero
            while ($m > 0 && gmp_cmp($m & 0x0f, $zero) === 0) {
                $m >>= 4;
                ++$e;
            }
        }
        // scale factor
        $scale = 0;
        while ($m > 0 && gmp_cmp($m & 0x01, $zero) === 0) {
            $m >>= 1;
            ++$scale;
        }
        $byte |= ($scale & 0x03) << 2;
        // encode exponent
        $exp_bytes = (new BigInt($e))->signedOctets();
        $exp_len = mb_strlen($exp_bytes, '8bit');
        if ($exp_len > 0xff) {
            throw new RangeException('Exponent encoding is too long.');
        }
        if ($exp_len <= 3) {
            $byte |= ($exp_len - 1) & 0x03;
            $bytes = chr($byte);
        } else {
            $byte |= 0x03;
            $bytes = chr($byte) . chr($exp_len);
        }
        $bytes .= $exp_bytes;
        // encode mantissa
        $bytes .= (new BigInt($m))->unsignedOctets();
        return $bytes;
    }

    /**
     * Encode in decimal format.
     */
    protected function _encodeDecimal(): string
    {
        // encode in NR3 decimal encoding
        return chr(0x03) . $this->nr3Val();
    }

    /**
     * Encode special value.
     */
    protected function _encodeSpecial(): string
    {
        return match ($this->_mantissa->intVal()) {
            1 => chr(0x40),
            -1 => chr(0x41),
            default => throw new LogicException('Invalid special value.'),
        };
    }

    protected static function _decodeFromDER(Identifier $identifier, string $data, int &$offset): ElementBase
    {
        $idx = $offset;
        $length = Length::expectFromDER($data, $idx)->intLength();
        // if length is zero, value is zero (spec 8.5.2)
        if (! $length) {
            $obj = new self(0, 0, 10);
        } else {
            $bytes = mb_substr($data, $idx, $length, '8bit');
            $byte = ord($bytes[0]);
            if (0x80 & $byte) { // bit 8 = 1
                $obj = self::_decodeBinaryEncoding($bytes);
            } elseif ($byte >> 6 === 0x00) { // bit 8 = 0, bit 7 = 0
                $obj = self::_decodeDecimalEncoding($bytes);
            } else { // bit 8 = 0, bit 7 = 1
                $obj = self::_decodeSpecialRealValue($bytes);
            }
        }
        $offset = $idx + $length;
        return $obj;
    }

    /**
     * Decode binary encoding.
     */
    protected static function _decodeBinaryEncoding(string $data)
    {
        $byte = ord($data[0]);
        // bit 7 is set if mantissa is negative
        $neg = (bool) (0x40 & $byte);
        $base = match (($byte >> 4) & 0x03) {
            0b00 => 2,
            0b01 => 8,
            0b10 => 16,
            default => throw new DecodeException('Reserved REAL binary encoding base not supported.'),
        };
        // scaling factor in bits 4 and 3
        $scale = ($byte >> 2) & 0x03;
        $idx = 1;
        // content length in bits 2 and 1
        $len = ($byte & 0x03) + 1;
        // if both bits are set, the next octet encodes the length
        if ($len > 3) {
            if (mb_strlen($data, '8bit') < 2) {
                throw new DecodeException('Unexpected end of data while decoding REAL exponent length.');
            }
            $len = ord($data[1]);
            $idx = 2;
        }
        if (mb_strlen($data, '8bit') < $idx + $len) {
            throw new DecodeException('Unexpected end of data while decoding REAL exponent.');
        }
        // decode exponent
        $octets = mb_substr($data, $idx, $len, '8bit');
        $exp = BigInt::fromSignedOctets($octets)->gmpObj();
        if ($base === 8) {
            $exp *= 3;
        } elseif ($base === 16) {
            $exp *= 4;
        }
        if (mb_strlen($data, '8bit') <= $idx + $len) {
            throw new DecodeException('Unexpected end of data while decoding REAL mantissa.');
        }
        // decode mantissa
        $octets = mb_substr($data, $idx + $len, null, '8bit');
        $n = BigInt::fromUnsignedOctets($octets)->gmpObj();
        $n *= 2 ** $scale;
        if ($neg) {
            $n = gmp_neg($n);
        }
        return new self($n, $exp, 2);
    }

    /**
     * Decode decimal encoding.
     */
    protected static function _decodeDecimalEncoding(string $data): self
    {
        $nr = ord($data[0]) & 0x3f;
        if (! in_array($nr, [1, 2, 3], true)) {
            throw new DecodeException('Unsupported decimal encoding form.');
        }
        $str = mb_substr($data, 1, null, '8bit');
        return self::fromString($str);
    }

    /**
     * Decode special encoding.
     */
    protected static function _decodeSpecialRealValue(string $data): self
    {
        if (mb_strlen($data, '8bit') !== 1) {
            throw new DecodeException('SpecialRealValue must have one content octet.');
        }
        $byte = ord($data[0]);
        if ($byte === 0x40) {   // positive infinity
            return self::_fromInfinite(INF);
        }
        if ($byte === 0x41) {   // negative infinity
            return self::_fromInfinite(-INF);
        }
        throw new DecodeException('Invalid SpecialRealValue encoding.');
    }

    /**
     * Prepare value for binary encoding.
     *
     * @return array (int) base, (int) sign, (\GMP) mantissa and (\GMP) exponent
     */
    protected function _prepareBinaryEncoding(): array
    {
        $base = 2;
        $m = $this->_mantissa->gmpObj();
        $ms = gmp_sign($m);
        $m = gmp_abs($m);
        $e = $this->_exponent->gmpObj();
        $es = gmp_sign($e);
        $e = gmp_abs($e);
        $zero = gmp_init(0);
        $three = gmp_init(3, 10);
        $four = gmp_init(4, 10);
        // DER uses only base 2 binary encoding
        if (! $this->_strictDer) {
            if (gmp_cmp(gmp_mod($e, $four), $zero) === 0) {
                $base = 16;
                $e = gmp_div_q($e, 4);
            } elseif (gmp_cmp(gmp_mod($e, $three), $zero) === 0) {
                $base = 8;
                $e = gmp_div_q($e, 3);
            }
        }
        return [$base, $ms, $m, $e * $es];
    }

    /**
     * Initialize from INF or -INF.
     */
    private static function _fromInfinite(float $inf): self
    {
        return new self($inf === -INF ? -1 : 1, self::INF_EXPONENT, 2);
    }

    /**
     * Parse IEEE 754 big endian formatted double precision float to base 2 mantissa and exponent.
     *
     * @param string $octets 64 bits
     *
     * @return GMP[] Tuple of mantissa and exponent
     */
    private static function _parse754Double(string $octets): array
    {
        $n = gmp_import($octets, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
        // sign bit
        $neg = gmp_testbit($n, 63);
        // 11 bits of biased exponent
        $exp = (gmp_and($n, '0x7ff0000000000000') >> 52) + self::EXP_BIAS;
        // 52 bits of mantissa
        $man = gmp_and($n, '0xfffffffffffff');
        // zero, ASN.1 doesn't differentiate -0 from +0
        $zero = gmp_init(0);
        if ($exp === self::EXP_BIAS && gmp_cmp($man, $zero) === 0) {
            return [gmp_init(0, 10), gmp_init(0, 10)];
        }
        // denormalized value, shift binary point
        if ($exp === self::EXP_BIAS) {
            ++$exp;
        }
        // normalized value, insert implicit leading one before the binary point
        else {
            gmp_setbit($man, 52);
        }
        // find the last fraction bit that is set
        $last = gmp_scan1($man, 0);
        $bits_for_fraction = 52 - $last;
        // adjust mantissa and exponent so that we have integer values
        $man >>= $last;
        $exp -= $bits_for_fraction;
        // negate mantissa if number was negative
        if ($neg) {
            $man = gmp_neg($man);
        }
        return [$man, $exp];
    }

    /**
     * Parse textual REAL number to base 10 mantissa and exponent.
     *
     * @param string $str Number
     *
     * @return GMP[] Tuple of mantissa and exponent
     */
    private static function _parseString(string $str): array
    {
        // PHP exponent format
        if (preg_match(self::PHP_EXPONENT_DNUM, $str, $match)) {
            [$m, $e] = self::_parsePHPExponentMatch($match);
        }
        // NR3 format
        elseif (preg_match(self::NR3_REGEX, $str, $match)) {
            [$m, $e] = self::_parseNR3Match($match);
        }
        // NR2 format
        elseif (preg_match(self::NR2_REGEX, $str, $match)) {
            [$m, $e] = self::_parseNR2Match($match);
        }
        // NR1 format
        elseif (preg_match(self::NR1_REGEX, $str, $match)) {
            [$m, $e] = self::_parseNR1Match($match);
        }
        // invalid number
        else {
            throw new UnexpectedValueException("{$str} could not be parsed to REAL.");
        }
        // normalize so that mantsissa has no trailing zeroes
        $zero = gmp_init(0);
        $ten = gmp_init(10, 10);
        while (gmp_cmp($m, $zero) !== 0 && gmp_cmp(gmp_mod($m, $ten), $zero) === 0) {
            $m = gmp_div($m, $ten);
            $e = gmp_add($e, 1);
        }
        return [$m, $e];
    }

    /**
     * Parse PHP form float to base 10 mantissa and exponent.
     *
     * @param array $match Regexp match
     *
     * @return GMP[] Tuple of mantissa and exponent
     */
    private static function _parsePHPExponentMatch(array $match): array
    {
        // mantissa sign
        $ms = $match['ms'] === '-' ? -1 : 1;
        $m_parts = explode('.', (string) $match['m']);
        // integer part of the mantissa
        $int = ltrim($m_parts[0], '0');
        // exponent sign
        $es = $match['es'] === '-' ? -1 : 1;
        // signed exponent
        $e = gmp_init($match['e'], 10) * $es;
        // if mantissa had fractional part
        if (count($m_parts) === 2) {
            $frac = rtrim($m_parts[1], '0');
            $e -= mb_strlen($frac, '8bit');
            $int .= $frac;
        }
        $m = gmp_init($int, 10) * $ms;
        return [$m, $e];
    }

    /**
     * Parse NR3 form number to base 10 mantissa and exponent.
     *
     * @param array $match Regexp match
     *
     * @return GMP[] Tuple of mantissa and exponent
     */
    private static function _parseNR3Match(array $match): array
    {
        // mantissa sign
        $ms = $match['ms'] === '-' ? -1 : 1;
        // explode mantissa to integer and fraction parts
        [$int, $frac] = explode('.', (string) str_replace(',', '.', $match['m']));
        $int = ltrim($int, '0');
        $frac = rtrim($frac, '0');
        // exponent sign
        $es = $match['es'] === '-' ? -1 : 1;
        // signed exponent
        $e = gmp_init($match['e'], 10) * $es;
        // shift exponent by the number of base 10 fractions
        $e -= mb_strlen($frac, '8bit');
        // insert fractions to integer part and produce signed mantissa
        $int .= $frac;
        if ($int === '') {
            $int = '0';
        }
        $m = gmp_init($int, 10) * $ms;
        return [$m, $e];
    }

    /**
     * Parse NR2 form number to base 10 mantissa and exponent.
     *
     * @param array $match Regexp match
     *
     * @return GMP[] Tuple of mantissa and exponent
     */
    private static function _parseNR2Match(array $match): array
    {
        $sign = $match['s'] === '-' ? -1 : 1;
        // explode decimal number to integer and fraction parts
        [$int, $frac] = explode('.', (string) str_replace(',', '.', $match['d']));
        $int = ltrim($int, '0');
        $frac = rtrim($frac, '0');
        // shift exponent by the number of base 10 fractions
        $e = gmp_init(0, 10);
        $e -= mb_strlen($frac, '8bit');
        // insert fractions to integer part and produce signed mantissa
        $int .= $frac;
        if ($int === '') {
            $int = '0';
        }
        $m = gmp_init($int, 10) * $sign;
        return [$m, $e];
    }

    /**
     * Parse NR1 form number to base 10 mantissa and exponent.
     *
     * @param array $match Regexp match
     *
     * @return GMP[] Tuple of mantissa and exponent
     */
    private static function _parseNR1Match(array $match): array
    {
        $sign = $match['s'] === '-' ? -1 : 1;
        $int = ltrim($match['i'], '0');
        if ($int === '') {
            $int = '0';
        }
        $m = gmp_init($int, 10) * $sign;
        return [$m, gmp_init(0, 10)];
    }
}
