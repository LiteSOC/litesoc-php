<?php

declare(strict_types=1);

namespace LiteSOC\Exceptions;

/**
 * Exception thrown when feature is not available on current plan (403 Forbidden)
 *
 * This indicates the requested feature requires a higher subscription tier.
 * The Management API (alerts) requires a Pro or Enterprise plan.
 *
 * Upgrade your plan at: https://www.litesoc.io/pricing
 */
class PlanRestrictedException extends LiteSOCException
{
    /**
     * URL to upgrade plan
     */
    public const UPGRADE_URL = 'https://www.litesoc.io/pricing';

    private ?string $requiredPlan;

    public function __construct(
        string $message = 'This feature requires a Pro or Enterprise plan. Upgrade at: https://www.litesoc.io/pricing',
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

    /**
     * Get the URL to upgrade the plan
     */
    public function getUpgradeUrl(): string
    {
        return self::UPGRADE_URL;
    }
}
