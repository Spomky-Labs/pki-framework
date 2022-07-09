<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\AttributeCertificate\Validation;

use DateTimeImmutable;
use SpomkyLabs\Pki\X509\Certificate\Extension\Target\Target;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;

/**
 * Provides configuration context for the attribute certificate validation.
 */
final class ACValidationConfig
{
    /**
     * Evaluation reference time.
     */
    private DateTimeImmutable $_evalTime;

    /**
     * Permitted targets.
     *
     * @var Target[]
     */
    private array $_targets;

    /**
     * Constructor.
     *
     * @param CertificationPath $_holderPath Certification path of the AC holder
     * @param CertificationPath $_issuerPath Certification path of the AC issuer
     */
    public function __construct(
        protected CertificationPath $_holderPath,
        protected CertificationPath $_issuerPath
    ) {
        $this->_evalTime = new DateTimeImmutable();
        $this->_targets = [];
    }

    /**
     * Get certification path of the AC's holder.
     */
    public function holderPath(): CertificationPath
    {
        return $this->_holderPath;
    }

    /**
     * Get certification path of the AC's issuer.
     */
    public function issuerPath(): CertificationPath
    {
        return $this->_issuerPath;
    }

    /**
     * Get self with given evaluation reference time.
     */
    public function withEvaluationTime(DateTimeImmutable $dt): self
    {
        $obj = clone $this;
        $obj->_evalTime = $dt;
        return $obj;
    }

    /**
     * Get the evaluation reference time.
     */
    public function evaluationTime(): DateTimeImmutable
    {
        return $this->_evalTime;
    }

    /**
     * Get self with permitted targets.
     */
    public function withTargets(Target ...$targets): self
    {
        $obj = clone $this;
        $obj->_targets = $targets;
        return $obj;
    }

    /**
     * Get array of permitted targets.
     *
     * @return Target[]
     */
    public function targets(): array
    {
        return $this->_targets;
    }
}
