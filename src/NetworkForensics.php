<?php

declare(strict_types=1);

namespace LiteSOC;

/**
 * Network forensics information (Pro/Enterprise plans only).
 * 
 * Contains network intelligence data including VPN, Tor, proxy detection,
 * and ISP/ASN information.
 * 
 * Note: Returns null for Free tier users.
 * 
 * @example
 * ```php
 * $alert = $litesoc->getAlert('alert_123');
 * if ($alert['forensics'] !== null) {
 *     $network = NetworkForensics::fromArray($alert['forensics']['network']);
 *     if ($network->isVpn) {
 *         echo "Alert originated from VPN";
 *     }
 *     echo "ASN: " . $network->asn;
 * }
 * ```
 */
class NetworkForensics
{
    /**
     * @param bool $isVpn Whether the IP is from a VPN provider
     * @param bool $isTor Whether the IP is a Tor exit node
     * @param bool $isProxy Whether the IP is from a proxy server
     * @param bool $isDatacenter Whether the IP is from a datacenter/cloud provider
     * @param bool $isMobile Whether the IP is from a mobile carrier
     * @param int|null $asn Autonomous System Number
     * @param string|null $asnOrg Autonomous System Organization name
     * @param string|null $isp Internet Service Provider name
     */
    public function __construct(
        public readonly bool $isVpn,
        public readonly bool $isTor,
        public readonly bool $isProxy,
        public readonly bool $isDatacenter,
        public readonly bool $isMobile,
        public readonly ?int $asn = null,
        public readonly ?string $asnOrg = null,
        public readonly ?string $isp = null,
    ) {}

    /**
     * Create a NetworkForensics instance from an API response array.
     *
     * @param array<string, mixed> $data The network forensics data from API response
     * @return self
     */
    public static function fromArray(array $data): self
    {
        return new self(
            isVpn: (bool) ($data['is_vpn'] ?? false),
            isTor: (bool) ($data['is_tor'] ?? false),
            isProxy: (bool) ($data['is_proxy'] ?? false),
            isDatacenter: (bool) ($data['is_datacenter'] ?? false),
            isMobile: (bool) ($data['is_mobile'] ?? false),
            asn: isset($data['asn']) ? (int) $data['asn'] : null,
            asnOrg: $data['asn_org'] ?? null,
            isp: $data['isp'] ?? null,
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
            'is_vpn' => $this->isVpn,
            'is_tor' => $this->isTor,
            'is_proxy' => $this->isProxy,
            'is_datacenter' => $this->isDatacenter,
            'is_mobile' => $this->isMobile,
            'asn' => $this->asn,
            'asn_org' => $this->asnOrg,
            'isp' => $this->isp,
        ];
    }
}
