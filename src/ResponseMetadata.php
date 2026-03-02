<?php

declare(strict_types=1);

namespace LiteSOC;

/**
 * ResponseMetadata - Plan and quota information from API responses
 *
 * This class captures metadata from API response headers including
 * plan information, data retention settings, and cutoff dates.
 *
 * Headers parsed:
 * - X-LiteSOC-Plan: Current plan name (e.g., "starter", "business", "enterprise")
 * - X-LiteSOC-Retention: Data retention period in days
 * - X-LiteSOC-Cutoff: Earliest accessible data timestamp (ISO 8601)
 */
final class ResponseMetadata
{
    /**
     * Current plan name
     *
     * @var string|null
     */
    public readonly ?string $plan;

    /**
     * Data retention period in days
     *
     * @var int|null
     */
    public readonly ?int $retentionDays;

    /**
     * Earliest accessible data timestamp (ISO 8601)
     *
     * @var string|null
     */
    public readonly ?string $cutoffDate;

    /**
     * Create a new ResponseMetadata instance
     *
     * @param string|null $plan Current plan name
     * @param int|null $retentionDays Data retention period in days
     * @param string|null $cutoffDate Earliest accessible data timestamp
     */
    public function __construct(
        ?string $plan = null,
        ?int $retentionDays = null,
        ?string $cutoffDate = null
    ) {
        $this->plan = $plan;
        $this->retentionDays = $retentionDays;
        $this->cutoffDate = $cutoffDate;
    }

    /**
     * Create ResponseMetadata from API response headers
     *
     * @param array<string, string|string[]> $headers Response headers
     * @return self
     */
    public static function fromHeaders(array $headers): self
    {
        // Normalize header names to lowercase for case-insensitive access
        $normalizedHeaders = [];
        foreach ($headers as $key => $value) {
            $normalizedHeaders[strtolower($key)] = is_array($value) ? ($value[0] ?? null) : $value;
        }

        $plan = $normalizedHeaders['x-litesoc-plan'] ?? null;
        
        // Parse retention days - API may return "30 days" or "30" format
        $retentionDays = null;
        $retentionStr = $normalizedHeaders['x-litesoc-retention'] ?? null;
        if ($retentionStr !== null) {
            // Handle both "30 days" and "30" formats
            $retentionStr = trim((string) $retentionStr);
            if (str_ends_with($retentionStr, ' days')) {
                $retentionStr = substr($retentionStr, 0, -5); // Remove " days" suffix
            }
            $retentionDays = is_numeric($retentionStr) ? (int) $retentionStr : null;
        }
        
        $cutoffDate = $normalizedHeaders['x-litesoc-cutoff'] ?? null;

        return new self($plan, $retentionDays, $cutoffDate);
    }

    /**
     * Check if plan information is available
     *
     * @return bool
     */
    public function hasPlanInfo(): bool
    {
        return $this->plan !== null;
    }

    /**
     * Check if retention information is available
     *
     * @return bool
     */
    public function hasRetentionInfo(): bool
    {
        return $this->retentionDays !== null;
    }

    /**
     * Get array representation
     *
     * @return array{plan: string|null, retentionDays: int|null, cutoffDate: string|null}
     */
    public function toArray(): array
    {
        return [
            'plan' => $this->plan,
            'retentionDays' => $this->retentionDays,
            'cutoffDate' => $this->cutoffDate,
        ];
    }
}
