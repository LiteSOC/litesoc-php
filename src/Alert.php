<?php

declare(strict_types=1);

namespace LiteSOC;

/**
 * Alert object returned from the Management API.
 * 
 * Represents a security alert detected by LiteSOC's threat detection engine.
 * 
 * @example
 * ```php
 * use LiteSOC\Alert;
 * 
 * $alertsData = $litesoc->getAlerts(['status' => 'open']);
 * foreach ($alertsData['data'] ?? [] as $alertData) {
 *     $alert = Alert::fromArray($alertData);
 *     echo "{$alert->title} - {$alert->severity}\n";
 *     if ($alert->resolvedBy !== null) {
 *         echo "  Resolved by: {$alert->resolvedBy}\n";
 *     }
 * }
 * ```
 */
class Alert
{
    /**
     * @param string $id Unique alert identifier
     * @param string $alertType Alert type (e.g., 'brute_force_attack', 'impossible_travel')
     * @param string $severity Alert severity ('low', 'medium', 'high', 'critical')
     * @param string $status Alert status ('open', 'acknowledged', 'resolved', 'dismissed')
     * @param string $title Human-readable alert title
     * @param string|null $description Detailed alert description
     * @param string|null $sourceIp Source IP address that triggered the alert
     * @param string|null $actorId Actor/user ID associated with the alert
     * @param string|null $createdAt ISO 8601 timestamp when alert was created
     * @param string|null $updatedAt ISO 8601 timestamp when alert was last updated
     * @param string|null $resolvedAt ISO 8601 timestamp when alert was resolved
     * @param string|null $resolvedBy User ID or identifier who resolved the alert
     * @param array<string, mixed>|null $metadata Additional metadata (may contain internal_notes, resolution_type, etc.)
     */
    public function __construct(
        public readonly string $id,
        public readonly string $alertType,
        public readonly string $severity,
        public readonly string $status,
        public readonly string $title,
        public readonly ?string $description = null,
        public readonly ?string $sourceIp = null,
        public readonly ?string $actorId = null,
        public readonly ?string $createdAt = null,
        public readonly ?string $updatedAt = null,
        public readonly ?string $resolvedAt = null,
        public readonly ?string $resolvedBy = null,
        public readonly ?array $metadata = null,
    ) {}

    /**
     * Create an Alert instance from an API response array.
     *
     * @param array<string, mixed> $data The alert data from API response
     * @return self
     */
    public static function fromArray(array $data): self
    {
        return new self(
            id: (string) ($data['id'] ?? ''),
            alertType: (string) ($data['alert_type'] ?? ''),
            severity: (string) ($data['severity'] ?? ''),
            status: (string) ($data['status'] ?? ''),
            title: (string) ($data['title'] ?? ''),
            description: $data['description'] ?? null,
            sourceIp: $data['source_ip'] ?? null,
            actorId: $data['actor_id'] ?? null,
            createdAt: $data['created_at'] ?? null,
            updatedAt: $data['updated_at'] ?? null,
            resolvedAt: $data['resolved_at'] ?? null,
            resolvedBy: $data['resolved_by'] ?? null,
            metadata: $data['metadata'] ?? null,
        );
    }

    /**
     * Convert to array for serialization.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'alert_type' => $this->alertType,
            'severity' => $this->severity,
            'status' => $this->status,
            'title' => $this->title,
            'description' => $this->description,
            'source_ip' => $this->sourceIp,
            'actor_id' => $this->actorId,
            'created_at' => $this->createdAt,
            'updated_at' => $this->updatedAt,
            'resolved_at' => $this->resolvedAt,
            'resolved_by' => $this->resolvedBy,
            'metadata' => $this->metadata,
        ];
    }
}
