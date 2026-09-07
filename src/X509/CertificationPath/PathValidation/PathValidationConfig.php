<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\CertificationPath\PathValidation;

use function array_values;
use DateTimeImmutable;
use LogicException;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\PolicyInformation;

/**
 * Configuration for the certification path validation process.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-6.1.1
 */
final class PathValidationConfig
{
    /**
     * List of acceptable policy identifiers.
     *
     * @var string[]
     */
    private array $policySet;

    /**
     * Trust anchor certificate.
     *
     * If not set, path validation uses the first certificate of the path.
     */
    private ?Certificate $trustAnchor = null;

    /**
     * Whether policy mapping in inhibited.
     *
     * Setting this to true disallows policy mapping.
     */
    private bool $policyMappingInhibit;

    /**
     * Whether the path must be valid for at least one policy in the initial policy set.
     */
    private bool $explicitPolicy;

    /**
     * Whether anyPolicy OID processing should be inhibited.
     *
     * Setting this to true disallows the usage of anyPolicy.
     */
    private bool $anyPolicyInhibit;

    /**
     * OID's of the critical certificate extensions the application processes by its own means.
     *
     * They are accepted by the validator in addition to the ones it processes itself.
     *
     * @var list<string>
     */
    private array $additionalCriticalExtensions;

    /**
     * @param DateTimeImmutable $dateTime Reference date and time
     * @param int $maxLength Maximum certification path length
     */
    private function __construct(
        private DateTimeImmutable $dateTime,
        private int $maxLength
    ) {
        $this->policySet = [PolicyInformation::OID_ANY_POLICY];
        $this->policyMappingInhibit = false;
        $this->explicitPolicy = false;
        $this->anyPolicyInhibit = false;
        $this->additionalCriticalExtensions = [];
    }

    public static function create(DateTimeImmutable $dateTime, int $maxLength): self
    {
        return new self($dateTime, $maxLength);
    }

    /**
     * Get default configuration.
     */
    public static function defaultConfig(): self
    {
        return self::create(new DateTimeImmutable(), 3);
    }

    /**
     * Get self with maximum path length.
     */
    public function withMaxLength(int $length): self
    {
        $obj = clone $this;
        $obj->maxLength = $length;
        return $obj;
    }

    /**
     * Get self with reference date and time.
     */
    public function withDateTime(DateTimeImmutable $dt): self
    {
        $obj = clone $this;
        $obj->dateTime = $dt;
        return $obj;
    }

    /**
     * Get self with trust anchor certificate.
     */
    public function withTrustAnchor(Certificate $ca): self
    {
        $obj = clone $this;
        $obj->trustAnchor = $ca;
        return $obj;
    }

    /**
     * Get self with initial-policy-mapping-inhibit set.
     */
    public function withPolicyMappingInhibit(bool $flag): self
    {
        $obj = clone $this;
        $obj->policyMappingInhibit = $flag;
        return $obj;
    }

    /**
     * Get self with initial-explicit-policy set.
     */
    public function withExplicitPolicy(bool $flag): self
    {
        $obj = clone $this;
        $obj->explicitPolicy = $flag;
        return $obj;
    }

    /**
     * Get self with initial-any-policy-inhibit set.
     */
    public function withAnyPolicyInhibit(bool $flag): self
    {
        $obj = clone $this;
        $obj->anyPolicyInhibit = $flag;
        return $obj;
    }

    /**
     * Get self with the OID's of the critical extensions the application processes by its own means.
     *
     * The path validation rejects any certificate carrying a critical extension it cannot process. Use this method to
     * declare the extensions handled outside of the validator, so that they no longer cause a rejection.
     *
     * @param string ...$oids List of extension OID's
     */
    public function withAdditionalCriticalExtensions(string ...$oids): self
    {
        $obj = clone $this;
        $obj->additionalCriticalExtensions = array_values($oids);
        return $obj;
    }

    /**
     * Get self with user-initial-policy-set set to policy OIDs.
     *
     * @param string ...$policies List of policy OIDs
     */
    public function withPolicySet(string ...$policies): self
    {
        $obj = clone $this;
        $obj->policySet = $policies;
        return $obj;
    }

    /**
     * Get maximum certification path length.
     */
    public function maxLength(): int
    {
        return $this->maxLength;
    }

    /**
     * Get reference date and time.
     */
    public function dateTime(): DateTimeImmutable
    {
        return $this->dateTime;
    }

    /**
     * Get user-initial-policy-set.
     *
     * @return string[] Array of OID's
     */
    public function policySet(): array
    {
        return $this->policySet;
    }

    /**
     * Check whether trust anchor certificate is set.
     */
    public function hasTrustAnchor(): bool
    {
        return isset($this->trustAnchor);
    }

    /**
     * Get trust anchor certificate.
     */
    public function trustAnchor(): Certificate
    {
        if (! $this->hasTrustAnchor()) {
            throw new LogicException('No trust anchor.');
        }
        return $this->trustAnchor;
    }

    public function policyMappingInhibit(): bool
    {
        return $this->policyMappingInhibit;
    }

    public function explicitPolicy(): bool
    {
        return $this->explicitPolicy;
    }

    public function anyPolicyInhibit(): bool
    {
        return $this->anyPolicyInhibit;
    }

    /**
     * Get the OID's of the critical extensions the application processes by its own means.
     *
     * @return list<string> Array of OID's
     */
    public function additionalCriticalExtensions(): array
    {
        return $this->additionalCriticalExtensions;
    }
}
