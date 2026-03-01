# Changelog

All notable changes to the LiteSOC PHP SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.0] - 2026-03-02

### Changed

#### Management API Enhancements
- **`resolveAlert()`** - API body now sends `['action' => 'resolve', 'resolution_type' => ..., 'internal_notes' => ...]` to match API spec
- **`markAlertSafe()`** - API body now sends `['action' => 'mark_safe', 'internal_notes' => ...]` to match API spec

### Added
- **`setHttpClient()`** - New method to inject custom Guzzle HTTP client (for testing)
- Added 15 new Management API tests with mocked HTTP responses

### Fixed
- Aligned SDK methods with API codebase requirements for PATCH /alerts/:id endpoint
- Fixed docstring parameter name from `event` to `event_name` in `getEvents()`
- Updated test suite (88 tests, 230 assertions, 95.61% coverage for core class)

## [2.1.0] - 2026-03-01

### Added

#### Alert Model Class
- **`Alert`** - New class representing security alerts with typed properties
  - `triggerEventId` - New property linking alerts to their triggering event
  - `forensics` - New property containing network intelligence and location data
  - `fromArray()` - Create Alert from API response array
  - `toArray()` - Serialize Alert to array

#### Forensics Classes (Pro/Enterprise)
- **`Forensics`** - Container class for network and location forensics data
  - `fromArray()` - Create from API response, returns null for Free tier
  - `toArray()` - Serialize to array

- **`NetworkForensics`** - Network intelligence class including:
  - `isVpn`, `isTor`, `isProxy`, `isDatacenter`, `isMobile` - Boolean flags
  - `asn`, `asnOrg`, `isp` - Autonomous System and ISP information
  - `fromArray()`, `toArray()` - Serialization methods

- **`LocationForensics`** - GeoIP location class including:
  - `city`, `region`, `countryCode`, `countryName` - Location strings
  - `latitude`, `longitude` - Coordinates
  - `timezone` - IANA timezone identifier
  - `fromArray()`, `toArray()` - Serialization methods

### Changed
- **Version** - Updated to 2.1.0

### Notes
- `forensics` returns `null` for Free tier users - ensure null-safe access in your code
- `triggerEventId` may be `null` for alerts not triggered by a specific event
- All new classes use PHP 8.2+ readonly properties and constructor promotion

## [2.0.0] - 2025-06-17

### Added
- **Management API Support** - Query alerts and events programmatically (Business/Enterprise plans)
  - `getAlerts(array $filters)` - Retrieve alerts with optional filters (severity, status, limit, offset)
  - `getAlert(string $alertId)` - Get a specific alert by ID
  - `resolveAlert(string $alertId, string $type, string $notes)` - Resolve an alert
  - `markAlertSafe(string $alertId, string $notes)` - Mark an alert as false positive
  - `getEvents(int $limit, array $filters)` - Retrieve events with optional filters
  - `getEvent(string $eventId)` - Get a specific event by ID

- **SecurityEvents Class** - New class with 26 standard security event constants
  - Consistent naming with Node.js and Python SDKs
  - Includes `all()` method to get all events as an array
  - Includes `isValid(string $event)` method to validate event types

- **Custom Exception Classes** - Specific exceptions for different error scenarios
  - `LiteSOCException` - Base exception for all SDK errors
  - `AuthenticationException` - Invalid or missing API key (401)
  - `RateLimitException` - Rate limit exceeded (429) with `getRetryAfter()` method
  - `PlanRestrictedException` - Feature requires higher plan (403) with `getRequiredPlan()` method

- **Base URL Configuration** - New `base_url` option for custom deployments
  - Replaces the need to specify full `endpoint` path
  - Defaults to `https://api.litesoc.io`
  - Laravel config updated with `LITESOC_BASE_URL` env variable

- **Upgrade Hints for 403 Errors** - `PlanRestrictedException` now includes upgrade hint in message

### Changed
- **Version** - Updated to 2.0.0
- **Default Timeout** - Reduced from 30 seconds to **5 seconds** for faster failure detection
- **Authentication Header** - Changed from `Authorization: Bearer` to `X-API-Key` header
- **User-Agent** - Changed from `litesoc-php/VERSION` to `litesoc-php-sdk/VERSION`
- **Laravel Integration** - Updated `LiteSOCServiceProvider` to support `base_url`
- **Test Coverage** - Expanded to 52 tests covering all new functionality

### Backward Compatible
- The `endpoint` option is still supported for backward compatibility
- All existing `EventType` constants remain unchanged
- All existing tracking methods work exactly as before

## [1.2.0] - 2026-02-25

### Changed
- **New API Endpoint** - Updated default endpoint from `https://litesoc.io/api/v1/collect` to `https://api.litesoc.io/collect`
  - Cleaner subdomain-based API architecture
  - Improved routing and performance
  - No breaking changes - existing custom endpoints continue to work

### Notes
- If you're using a custom `endpoint` configuration, no changes needed
- The new endpoint provides the same functionality with improved infrastructure

## [1.1.0] - 2026-02-22

### Added
- **26 Standard Security Events** - Reorganized event constants into 5 categories:
  - Auth (8 events): `login_success`, `login_failed`, `logout`, `password_reset`, `mfa_enabled`, `mfa_disabled`, `session_expired`, `token_refreshed`
  - Authz (4 events): `role_changed`, `permission_granted`, `permission_revoked`, `access_denied`
  - Admin (7 events): `privilege_escalation`, `user_impersonation`, `settings_changed`, `api_key_created`, `api_key_revoked`, `user_suspended`, `user_deleted`
  - Data (3 events): `bulk_delete`, `sensitive_access`, `export`
  - Security (4 events): `suspicious_activity`, `rate_limit_exceeded`, `ip_blocked`, `brute_force_detected`
- **Security Intelligence Documentation** - Added documentation for auto-enrichment features:
  - GeoIP Enrichment (country, city, coordinates)
  - Network Intelligence (VPN, Tor, Proxy, Datacenter detection)
  - Threat Scoring (Low → Critical severity auto-classification)
- Organized `EventType` class constants by category with clear comments

### Changed
- Updated `EventType.php` with 26 standard events as primary constants
- Updated README with Security Intelligence section and 26-event table
- Emphasized importance of `user_ip` parameter for full enrichment features

### Deprecated
- Legacy event constants (e.g., `AUTH_PASSWORD_CHANGED`) still supported for backward compatibility

## [1.0.1] - Previous Release

- Initial stable release with basic event tracking and Laravel integration
