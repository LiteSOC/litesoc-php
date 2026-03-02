<?php

declare(strict_types=1);

namespace LiteSOC;

/**
 * Event object returned from the Management API.
 * 
 * Represents a security event tracked by LiteSOC.
 * 
 * Note: Free tier users will have forensic fields (is_vpn, is_tor, is_proxy,
 * is_datacenter, latitude, longitude, city) returned as null (redacted).
 * 
 * @example
 * ```php
 * use LiteSOC\Event;
 * 
 * $eventsData = $litesoc->getEvents(50, ['event_name' => 'auth.login_failed']);
 * foreach ($eventsData['data'] ?? [] as $eventData) {
 *     $event = Event::fromArray($eventData);
 *     echo "{$event->eventName} from {$event->userIp}\n";
 *     if ($event->isVpn) {
 *         echo "  Warning: VPN detected\n";
 *     }
 * }
 * ```
 */
class Event
{
    /**
     * @param string $id Unique event identifier (UUID)
     * @param string $orgId Organization ID
     * @param string $eventName Event type (e.g., 'auth.login_failed')
     * @param string|null $actorId Actor/user ID associated with the event
     * @param string|null $userIp End-user's IP address
     * @param string|null $serverIp Server IP that processed the event
     * @param string|null $countryCode ISO 3166-1 alpha-2 country code
     * @param string|null $city City name (Pro/Enterprise only, null for Free)
     * @param bool|null $isVpn Whether IP is from a VPN provider (Pro/Enterprise only)
     * @param bool|null $isTor Whether IP is a Tor exit node (Pro/Enterprise only)
     * @param bool|null $isProxy Whether IP is from a proxy service (Pro/Enterprise only)
     * @param bool|null $isDatacenter Whether IP is from a datacenter/cloud provider (Pro/Enterprise only)
     * @param float|null $latitude GPS latitude coordinate (Pro/Enterprise only)
     * @param float|null $longitude GPS longitude coordinate (Pro/Enterprise only)
     * @param string $severity Event severity ('info', 'warning', 'critical')
     * @param array<string, mixed>|null $metadata Additional event metadata
     * @param string|null $createdAt ISO 8601 timestamp when event was created
     */
    public function __construct(
        public readonly string $id,
        public readonly string $orgId,
        public readonly string $eventName,
        public readonly ?string $actorId = null,
        public readonly ?string $userIp = null,
        public readonly ?string $serverIp = null,
        public readonly ?string $countryCode = null,
        public readonly ?string $city = null,
        public readonly ?bool $isVpn = null,
        public readonly ?bool $isTor = null,
        public readonly ?bool $isProxy = null,
        public readonly ?bool $isDatacenter = null,
        public readonly ?float $latitude = null,
        public readonly ?float $longitude = null,
        public readonly string $severity = 'info',
        public readonly ?array $metadata = null,
        public readonly ?string $createdAt = null,
    ) {}

    /**
     * Create an Event instance from an API response array.
     *
     * @param array<string, mixed> $data The event data from API response
     * @return self
     */
    public static function fromArray(array $data): self
    {
        return new self(
            id: (string) ($data['id'] ?? ''),
            orgId: (string) ($data['org_id'] ?? ''),
            eventName: (string) ($data['event_name'] ?? ''),
            actorId: $data['actor_id'] ?? null,
            userIp: $data['user_ip'] ?? null,
            serverIp: $data['server_ip'] ?? null,
            countryCode: $data['country_code'] ?? null,
            city: $data['city'] ?? null,
            isVpn: isset($data['is_vpn']) ? (bool) $data['is_vpn'] : null,
            isTor: isset($data['is_tor']) ? (bool) $data['is_tor'] : null,
            isProxy: isset($data['is_proxy']) ? (bool) $data['is_proxy'] : null,
            isDatacenter: isset($data['is_datacenter']) ? (bool) $data['is_datacenter'] : null,
            latitude: isset($data['latitude']) ? (float) $data['latitude'] : null,
            longitude: isset($data['longitude']) ? (float) $data['longitude'] : null,
            severity: (string) ($data['severity'] ?? 'info'),
            metadata: $data['metadata'] ?? null,
            createdAt: $data['created_at'] ?? null,
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
            'org_id' => $this->orgId,
            'event_name' => $this->eventName,
            'actor_id' => $this->actorId,
            'user_ip' => $this->userIp,
            'server_ip' => $this->serverIp,
            'country_code' => $this->countryCode,
            'city' => $this->city,
            'is_vpn' => $this->isVpn,
            'is_tor' => $this->isTor,
            'is_proxy' => $this->isProxy,
            'is_datacenter' => $this->isDatacenter,
            'latitude' => $this->latitude,
            'longitude' => $this->longitude,
            'severity' => $this->severity,
            'metadata' => $this->metadata,
            'created_at' => $this->createdAt,
        ];
    }

    /**
     * Check if forensic fields are available (not redacted).
     * 
     * Free tier users have forensic fields redacted (null).
     * Pro/Enterprise users have full forensic data.
     *
     * @return bool True if forensic data is available
     */
    public function hasForensics(): bool
    {
        // If any forensic field is non-null, forensics are available
        return $this->isVpn !== null 
            || $this->isTor !== null 
            || $this->isProxy !== null
            || $this->latitude !== null;
    }
}
