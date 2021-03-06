<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\ASN1\Type\Primitive;

use DateTimeImmutable;
use DateTimeZone;
use function intval;
use function mb_strlen;
use SpomkyLabs\Pki\ASN1\Component\Identifier;
use SpomkyLabs\Pki\ASN1\Component\Length;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Feature\ElementBase;
use SpomkyLabs\Pki\ASN1\Type\BaseTime;
use SpomkyLabs\Pki\ASN1\Type\PrimitiveType;
use SpomkyLabs\Pki\ASN1\Type\UniversalClass;
use Throwable;
use UnexpectedValueException;

/**
 * Implements *GeneralizedTime* type.
 */
final class GeneralizedTime extends BaseTime
{
    use UniversalClass;
    use PrimitiveType;

    /**
     * Regular expression to parse date.
     *
     * DER restricts format to UTC timezone (Z suffix).
     *
     * @var string
     */
    final public const REGEX = '#^' .
    '(\d\d\d\d)' . // YYYY
    '(\d\d)' . // MM
    '(\d\d)' . // DD
    '(\d\d)' . // hh
    '(\d\d)' . // mm
    '(\d\d)' . // ss
    '(?:\.(\d+))?' . // frac
    'Z' . // TZ
    '$#';

    /**
     * Cached formatted date.
     */
    private ?string $_formatted = null;

    public function __construct(DateTimeImmutable $dt)
    {
        $this->typeTag = self::TYPE_GENERALIZED_TIME;
        parent::__construct($dt);
    }

    /**
     * Clear cached variables on clone.
     */
    public function __clone()
    {
        $this->_formatted = null;
    }

    public static function fromString(string $time, ?string $tz = null): static
    {
        return new static(new DateTimeImmutable($time, self::_createTimeZone($tz)));
    }

    protected function encodedAsDER(): string
    {
        if (! isset($this->_formatted)) {
            $dt = $this->_dateTime->setTimezone(new DateTimeZone('UTC'));
            $this->_formatted = $dt->format('YmdHis');
            // if fractions were used
            $frac = $dt->format('u');
            if (intval($frac) !== 0) {
                $frac = rtrim($frac, '0');
                $this->_formatted .= ".{$frac}";
            }
            // timezone
            $this->_formatted .= 'Z';
        }
        return $this->_formatted;
    }

    protected static function decodeFromDER(Identifier $identifier, string $data, int &$offset): ElementBase
    {
        $idx = $offset;
        $length = Length::expectFromDER($data, $idx)->intLength();
        $str = mb_substr($data, $idx, $length, '8bit');
        $idx += $length;
        /** @var string[] $match */
        if (! preg_match(self::REGEX, $str, $match)) {
            throw new DecodeException('Invalid GeneralizedTime format.');
        }
        [, $year, $month, $day, $hour, $minute, $second] = $match;
        // if fractions match, there's at least one digit
        if (isset($match[7])) {
            $frac = $match[7];
            // DER restricts trailing zeroes in fractional seconds component
            if ($frac[mb_strlen((string) $frac, '8bit') - 1] === '0') {
                throw new DecodeException('Fractional seconds must omit trailing zeroes.');
            }
        } else {
            $frac = '0';
        }
        $time = $year . $month . $day . $hour . $minute . $second . '.' . $frac .
            self::TZ_UTC;
        $dt = DateTimeImmutable::createFromFormat('!YmdHis.uT', $time, new DateTimeZone('UTC'));
        if (! $dt) {
            throw new DecodeException(
                'Failed to decode GeneralizedTime: ' .
                self::_getLastDateTimeImmutableErrorsStr()
            );
        }
        $offset = $idx;
        return new self($dt);
    }

    /**
     * Create `DateTimeZone` object from string.
     */
    private static function _createTimeZone(?string $tz): DateTimeZone
    {
        try {
            return new DateTimeZone($tz ?? 'UTC');
        } catch (Throwable $e) {
            throw new UnexpectedValueException('Invalid timezone.', 0, $e);
        }
    }
}
