<?php

declare(strict_types=1);

namespace LiteSOC;

/**
 * Forensics data attached to alerts (Pro/Enterprise plans only).
 * 
 * Contains network intelligence and location data for threat analysis.
 * 
 * Note: Returns null for Free tier users.
 * 
 * @example
 * ```php
 * $alert = $litesoc->getAlert('alert_123');
 * if ($alert['forensics'] !== null) {
 *     $forensics = Forensics::fromArray($alert['forensics']);
 *     if ($forensics->network->isVpn) {
 *         echo "Alert originated from VPN";
 *     }
 *     echo "Location: " . $forensics->location->city . ", " . $forensics->location->countryCode;
 * }
 * ```
 */
class Forensics
{
    /**
     * @param NetworkForensics $network Network intelligence data
     * @param LocationForensics $location Location/GeoIP data
     */
    public function __construct(
        public readonly NetworkForensics $network,
        public readonly LocationForensics $location,
    ) {}

    /**
     * Create a Forensics instance from an API response array.
     * 
     * Returns null if the input data is null (Free tier).
     *
     * @param array<string, mixed>|null $data The forensics data from API response, or null
     * @return self|null Forensics instance, or null if data is null (Free tier)
     */
    public static function fromArray(?array $data): ?self
    {
        if ($data === null) {
            return null;
        }

        return new self(
            network: NetworkForensics::fromArray($data['network'] ?? []),
            location: LocationForensics::fromArray($data['location'] ?? []),
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
            'network' => $this->network->toArray(),
            'location' => $this->location->toArray(),
        ];
    }
}
