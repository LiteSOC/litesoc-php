<?php

declare(strict_types=1);

namespace LiteSOC;

/**
 * Location forensics information (Pro/Enterprise plans only).
 * 
 * Contains GeoIP location data including city, country, and coordinates.
 * 
 * Note: Returns null for Free tier users.
 * 
 * @example
 * ```php
 * $alert = $litesoc->getAlert('alert_123');
 * if ($alert['forensics'] !== null) {
 *     $location = LocationForensics::fromArray($alert['forensics']['location']);
 *     echo "City: " . $location->city;
 *     echo "Country: " . $location->countryCode;
 * }
 * ```
 */
class LocationForensics
{
    /**
     * @param string|null $city City name
     * @param string|null $region Region/state name
     * @param string|null $countryCode ISO 3166-1 alpha-2 country code (e.g., 'US', 'GB')
     * @param string|null $countryName Full country name
     * @param float|null $latitude Latitude coordinate
     * @param float|null $longitude Longitude coordinate
     * @param string|null $timezone Timezone (e.g., 'America/New_York')
     */
    public function __construct(
        public readonly ?string $city = null,
        public readonly ?string $region = null,
        public readonly ?string $countryCode = null,
        public readonly ?string $countryName = null,
        public readonly ?float $latitude = null,
        public readonly ?float $longitude = null,
        public readonly ?string $timezone = null,
    ) {}

    /**
     * Create a LocationForensics instance from an API response array.
     *
     * @param array<string, mixed> $data The location forensics data from API response
     * @return self
     */
    public static function fromArray(array $data): self
    {
        return new self(
            city: $data['city'] ?? null,
            region: $data['region'] ?? null,
            countryCode: $data['country_code'] ?? null,
            countryName: $data['country_name'] ?? null,
            latitude: isset($data['latitude']) ? (float) $data['latitude'] : null,
            longitude: isset($data['longitude']) ? (float) $data['longitude'] : null,
            timezone: $data['timezone'] ?? null,
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
            'city' => $this->city,
            'region' => $this->region,
            'country_code' => $this->countryCode,
            'country_name' => $this->countryName,
            'latitude' => $this->latitude,
            'longitude' => $this->longitude,
            'timezone' => $this->timezone,
        ];
    }
}
