<?php

declare(strict_types=1);

namespace LiteSOC\Exceptions;

/**
 * Exception thrown when feature is not available on current plan (403 Forbidden)
 *
 * This indicates the requested feature requires a higher subscription tier.
 * The Management API requires a Business or Enterprise plan.
 */
class PlanRestrictedException extends LiteSOCException
{
    private ?string $requiredPlan;

    public function __construct(
        string $message = 'This feature requires a Business or Enterprise plan',
        ?string $requiredPlan = null,
        ?string $responseBody = null,
        ?\Throwable $previous = null
    ) {
        parent::__construct($message, 403, $responseBody, $previous);
        $this->requiredPlan = $requiredPlan;
    }

    /**
     * Get the plan required to access this feature
     */
    public function getRequiredPlan(): ?string
    {
        return $this->requiredPlan;
    }
}
