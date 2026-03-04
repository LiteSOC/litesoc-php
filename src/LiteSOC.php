<?php

declare(strict_types=1);

namespace LiteSOC;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\RequestException;
use LiteSOC\Exceptions\LiteSOCException;
use LiteSOC\Exceptions\AuthenticationException;
use LiteSOC\Exceptions\NotFoundException;
use LiteSOC\Exceptions\RateLimitException;
use LiteSOC\Exceptions\PlanRestrictedException;
use LiteSOC\Exceptions\ValidationException;
use LiteSOC\ResponseMetadata;

/**
 * LiteSOC SDK for tracking security events
 *
 * @example
 * ```php
 * use LiteSOC\LiteSOC;
 *
 * $litesoc = new LiteSOC('your-api-key');
 *
 * // Track a login failure
 * $litesoc->track('auth.login_failed', [
 *     'actor_id' => 'user_123',
 *     'actor_email' => 'user@example.com',
 *     'user_ip' => '192.168.1.1',
 *     'metadata' => ['reason' => 'invalid_password']
 * ]);
 *
 * // Flush remaining events
 * $litesoc->flush();
 *
 * // Management API (Business/Enterprise plans)
 * $alerts = $litesoc->getAlerts(['severity' => 'critical']);
 * $events = $litesoc->getEvents(20);
 * ```
 */
class LiteSOC
{
    public const VERSION = '2.5.0';
    public const DEFAULT_BASE_URL = 'https://api.litesoc.io';

    private string $apiKey;
    private string $baseUrl;
    private string $endpoint;
    private bool $batching;
    private int $batchSize;
    private float $flushInterval;
    private bool $debug;
    private bool $silent;
    private float $timeout;

    /** @var array<int, array<string, mixed>> */
    private array $queue = [];

    private ?Client $client = null;

    /**
     * Last response metadata (plan info, retention, cutoff)
     */
    private ?ResponseMetadata $lastResponseMetadata = null;

    /**
     * Initialize the LiteSOC SDK
     *
     * @param string $apiKey Your LiteSOC API key (required)
     * @param array{
     *     base_url?: string,
     *     endpoint?: string,
     *     batching?: bool,
     *     batch_size?: int,
     *     flush_interval?: float,
     *     debug?: bool,
     *     silent?: bool,
     *     timeout?: float,
     * } $options Configuration options
     *
     * @throws \InvalidArgumentException If API key is not provided
     */
    public function __construct(string $apiKey, array $options = [])
    {
        if (empty($apiKey)) {
            throw new \InvalidArgumentException('LiteSOC: api_key is required');
        }

        $this->apiKey = $apiKey;
        $this->baseUrl = $options['base_url'] ?? self::DEFAULT_BASE_URL;
        // Support legacy 'endpoint' option for backward compatibility
        $this->endpoint = $options['endpoint'] ?? $this->baseUrl . '/collect';
        $this->batching = $options['batching'] ?? true;
        $this->batchSize = $options['batch_size'] ?? 10;
        $this->flushInterval = $options['flush_interval'] ?? 5.0;
        $this->debug = $options['debug'] ?? false;
        $this->silent = $options['silent'] ?? true;
        $this->timeout = $options['timeout'] ?? 5.0;

        $this->log('Initialized with base_url: ' . $this->baseUrl);
    }

    /**
     * Track a security event
     *
     * @param string $eventName The event type (e.g., 'auth.login_failed')
     * @param array{
     *     actor_id?: string,
     *     actor_email?: string,
     *     actor?: array{id: string, email?: string}|string,
     *     user_ip?: string,
     *     severity?: string,
     *     metadata?: array<string, mixed>,
     *     timestamp?: string|\DateTimeInterface,
     * } $options Event options
     *
     * **⚠️ CRITICAL: user_ip is REQUIRED for Behavioral AI features:**
     * - Impossible Travel detection
     * - Geo-Anomaly detection
     * - Forensic Maps visualization
     * - Network Intelligence (VPN/Tor/Proxy detection)
     *
     * Events without user_ip will have `network_intelligence: null` and `geolocation: null`.
     *
     * **Note:** The `severity` option is ignored. Severity is automatically assigned
     * server-side by LiteSOC based on threat intelligence to prevent tampering.
     */
    public function track(string $eventName, array $options = []): void
    {
        try {
            // Normalize actor
            $actor = null;

            if (isset($options['actor'])) {
                if (is_string($options['actor'])) {
                    $actor = [
                        'id' => $options['actor'],
                        'email' => $options['actor_email'] ?? null,
                    ];
                } elseif (is_array($options['actor'])) {
                    $actor = [
                        'id' => $options['actor']['id'],
                        'email' => $options['actor']['email'] ?? $options['actor_email'] ?? null,
                    ];
                }
            } elseif (isset($options['actor_id'])) {
                $actor = [
                    'id' => $options['actor_id'],
                    'email' => $options['actor_email'] ?? null,
                ];
            } elseif (isset($options['actor_email'])) {
                $actor = [
                    'id' => $options['actor_email'],
                    'email' => $options['actor_email'],
                ];
            }

            // Normalize timestamp
            $timestamp = $options['timestamp'] ?? null;
            if ($timestamp === null) {
                $timestamp = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format(\DateTimeInterface::ATOM);
            } elseif ($timestamp instanceof \DateTimeInterface) {
                $timestamp = $timestamp->format(\DateTimeInterface::ATOM);
            }

            // Build metadata
            $metadata = $options['metadata'] ?? [];
            $metadata['_sdk'] = 'litesoc-php';
            $metadata['_sdk_version'] = self::VERSION;

            // NOTE: Severity is intentionally NOT included in the payload.
            // Severity is automatically assigned server-side by LiteSOC to prevent tampering.
            // Any client-specified 'severity' option is ignored.

            // Create queued event
            $event = [
                'event' => $eventName,
                'actor' => $actor,
                'user_ip' => $options['user_ip'] ?? null,
                'metadata' => $metadata,
                'timestamp' => $timestamp,
                'retry_count' => 0,
            ];

            $this->log('Tracking event: ' . $eventName);

            if ($this->batching) {
                $this->queue[] = $event;
                $queueSize = count($this->queue);

                $this->log("Event queued. Queue size: {$queueSize}");

                if ($queueSize >= $this->batchSize) {
                    $this->flush();
                }
            } else {
                $this->sendEvents([$event]);
            }
        } catch (\Throwable $e) {
            $this->handleError('track', $e);
        }
    }

    /**
     * Flush all queued events to the server
     */
    public function flush(): void
    {
        if (empty($this->queue)) {
            $this->log('No events to flush');
            return;
        }

        $events = $this->queue;
        $this->queue = [];

        $this->log('Flushing ' . count($events) . ' events');

        try {
            $this->sendEvents($events);
        } catch (\Throwable $e) {
            $this->handleError('flush', $e);
        }
    }

    /**
     * Get the current queue size
     */
    public function getQueueSize(): int
    {
        return count($this->queue);
    }

    /**
     * Get the flush interval in seconds
     */
    public function getFlushInterval(): float
    {
        return $this->flushInterval;
    }

    /**
     * Clear all queued events without sending
     */
    public function clearQueue(): void
    {
        $this->queue = [];
        $this->log('Queue cleared');
    }

    /**
     * Shutdown the SDK gracefully
     */
    public function shutdown(): void
    {
        $this->log('Shutting down...');
        $this->flush();
        $this->log('Shutdown complete');
    }

    // ============================================
    // BATCH EVENT INGESTION
    // ============================================

    /**
     * Track a batch of security events in a single API request.
     *
     * Use this instead of calling track() in a loop when you already have a
     * set of events ready to send.  The SDK posts { "events": […] } to
     * /collect, which uses Redis pipelining server-side so the entire batch
     * costs one Upstash request unit instead of N.
     *
     * - Maximum 100 events per call.
     * - Quota is reserved atomically for the full batch.
     * - Rate-limit counter is incremented by the batch size, not by 1.
     *
     * @param array<int, array{
     *     event_name?: string,
     *     event?: string,
     *     actor_id?: string,
     *     actor_email?: string,
     *     actor?: string|array{id?: string, email?: string},
     *     user_ip?: string,
     *     metadata?: array<string, mixed>
     * }> $events
     * @return int Number of events accepted by the server
     * @throws \InvalidArgumentException If events array is empty or exceeds 100 items
     *
     * @example
     * ```php
     * $accepted = $litesoc->trackBatch([
     *     [
     *         'event_name'  => 'auth.login_success',
     *         'actor_id'    => $user->id,
     *         'actor_email' => $user->email,
     *         'user_ip'     => $request->ip(),
     *     ],
     *     [
     *         'event_name' => 'data.export',
     *         'actor_id'   => $user->id,
     *         'user_ip'    => $request->ip(),
     *         'metadata'   => ['rows' => 500, 'table' => 'orders'],
     *     ],
     * ]);
     * echo "{$accepted} events accepted";
     * ```
     */
    public function trackBatch(array $events): int
    {
        if (empty($events)) {
            throw new \InvalidArgumentException('trackBatch requires at least one event');
        }
        if (count($events) > 100) {
            throw new \InvalidArgumentException('trackBatch supports up to 100 events per call. Split into multiple calls.');
        }

        $payload = [];
        foreach ($events as $item) {
            $actor = null;
            if (isset($item['actor'])) {
                if (is_string($item['actor'])) {
                    $actor = ['id' => $item['actor'], 'email' => $item['actor_email'] ?? null];
                } elseif (is_array($item['actor'])) {
                    $actor = [
                        'id'    => $item['actor']['id'] ?? null,
                        'email' => $item['actor']['email'] ?? $item['actor_email'] ?? null,
                    ];
                }
            } elseif (isset($item['actor_id'])) {
                $actor = ['id' => $item['actor_id'], 'email' => $item['actor_email'] ?? null];
            } elseif (isset($item['actor_email'])) {
                $actor = ['id' => $item['actor_email'], 'email' => $item['actor_email']];
            }

            $metadata = $item['metadata'] ?? [];
            $metadata['_sdk']         = 'litesoc-php';
            $metadata['_sdk_version'] = self::VERSION;

            $payload[] = [
                'event'    => $item['event_name'] ?? $item['event'] ?? '',
                'actor'    => $actor,
                'user_ip'  => $item['user_ip'] ?? null,
                'metadata' => $metadata,
            ];
        }

        try {
            $client   = $this->getClient();
            $response = $client->post($this->endpoint, [
                'json'    => ['events' => $payload],
                'timeout' => $this->timeout,
            ]);

            /** @var array<string, mixed> $result */
            $result   = json_decode($response->getBody()->getContents(), true);
            $accepted = $result['queued'] ?? $result['inserted'] ?? count($payload);
            $this->log("trackBatch: {$accepted} event(s) accepted");

            return (int) $accepted;
        } catch (\Throwable $e) {
            $this->handleError('trackBatch', $e);
            return 0;
        }
    }

    // ============================================
    // CONVENIENCE METHODS
    // ============================================

    /**
     * Track a login failure event
     *
     * @param string $actorId User ID
     * @param array{actor_email?: string, user_ip?: string, metadata?: array<string, mixed>} $options
     */
    public function trackLoginFailed(string $actorId, array $options = []): void
    {
        $this->track('auth.login_failed', array_merge(['actor_id' => $actorId], $options));
    }

    /**
     * Track a login success event
     *
     * @param string $actorId User ID
     * @param array{actor_email?: string, user_ip?: string, metadata?: array<string, mixed>} $options
     */
    public function trackLoginSuccess(string $actorId, array $options = []): void
    {
        $this->track('auth.login_success', array_merge(['actor_id' => $actorId], $options));
    }

    /**
     * Track a privilege escalation event
     *
     * Note: Severity is automatically assigned server-side by LiteSOC.
     *
     * @param string $actorId User ID
     * @param array{actor_email?: string, user_ip?: string, metadata?: array<string, mixed>} $options
     */
    public function trackPrivilegeEscalation(string $actorId, array $options = []): void
    {
        // Note: Severity is assigned server-side, not passed from client
        $this->track('admin.privilege_escalation', array_merge([
            'actor_id' => $actorId,
        ], $options));
    }

    /**
     * Track a sensitive data access event
     *
     * Note: Severity is automatically assigned server-side by LiteSOC.
     *
     * @param string $actorId User ID
     * @param string $resource Resource accessed
     * @param array{actor_email?: string, user_ip?: string, metadata?: array<string, mixed>} $options
     */
    public function trackSensitiveAccess(string $actorId, string $resource, array $options = []): void
    {
        $metadata = $options['metadata'] ?? [];
        $metadata['resource'] = $resource;

        // Note: Severity is assigned server-side, not passed from client
        $this->track('data.sensitive_access', array_merge([
            'actor_id' => $actorId,
            'metadata' => $metadata,
        ], $options));
    }

    /**
     * Track a bulk delete event
     *
     * Note: Severity is automatically assigned server-side by LiteSOC.
     *
     * @param string $actorId User ID
     * @param int $recordCount Number of records deleted
     * @param array{actor_email?: string, user_ip?: string, metadata?: array<string, mixed>} $options
     *
     * NOTE: Severity is auto-assigned server-side for this high-risk event type.
     */
    public function trackBulkDelete(string $actorId, int $recordCount, array $options = []): void
    {
        $metadata = $options['metadata'] ?? [];
        $metadata['records_deleted'] = $recordCount;

        // Severity is assigned server-side for data.bulk_delete events
        $this->track('data.bulk_delete', array_merge([
            'actor_id' => $actorId,
            'metadata' => $metadata,
        ], $options));
    }

    /**
     * Track a role change event
     *
     * @param string $actorId User ID
     * @param string $oldRole Previous role
     * @param string $newRole New role
     * @param array{actor_email?: string, user_ip?: string, metadata?: array<string, mixed>} $options
     */
    public function trackRoleChanged(string $actorId, string $oldRole, string $newRole, array $options = []): void
    {
        $metadata = $options['metadata'] ?? [];
        $metadata['old_role'] = $oldRole;
        $metadata['new_role'] = $newRole;

        $this->track('authz.role_changed', array_merge([
            'actor_id' => $actorId,
            'metadata' => $metadata,
        ], $options));
    }

    /**
     * Track an access denied event
     *
     * @param string $actorId User ID
     * @param string $resource Resource that was denied
     * @param array{actor_email?: string, user_ip?: string, metadata?: array<string, mixed>} $options
     */
    public function trackAccessDenied(string $actorId, string $resource, array $options = []): void
    {
        $metadata = $options['metadata'] ?? [];
        $metadata['resource'] = $resource;

        $this->track('authz.access_denied', array_merge([
            'actor_id' => $actorId,
            'metadata' => $metadata,
        ], $options));
    }

    // ============================================
    // PRIVATE METHODS
    // ============================================

    /**
     * Send events to the LiteSOC API.
     *
     * Note: The API only accepts single events, so this method sends
     * Single event: flat payload { event, actor, … } (unchanged behaviour).
     * Multiple events: batch format { events: […] } — one HTTP request instead
     * of N, saving latency and Upstash request-unit costs.
     *
     * @param array<int, array<string, mixed>> $events
     */
    private function sendEvents(array $events): void
    {
        if (empty($events)) {
            return;
        }

        $client = $this->getClient();

        // Build payload once
        if (count($events) === 1) {
            $payload = $this->eventToPayload($events[0]);
        } else {
            $payload = ['events' => array_map([$this, 'eventToPayload'], $events)];
        }

        try {
            $response = $client->post($this->endpoint, [
                'json'    => $payload,
                'timeout' => $this->timeout,
            ]);

            /** @var array<string, mixed> $result */
            $result = json_decode($response->getBody()->getContents(), true);

            if (in_array($result['status'] ?? '', ['queued', 'inserted'], true)) {
                $count = $result['queued'] ?? $result['inserted'] ?? count($events);
                $this->log("Successfully sent {$count} event(s)");
            } elseif (isset($result['error'])) {
                throw new \RuntimeException((string) $result['error']);
            } else {
                $this->log('Successfully sent ' . count($events) . ' event(s)');
            }
        } catch (GuzzleException $e) {
            $this->log('Failed to send batch of ' . count($events) . ' event(s): ' . $e->getMessage());

            /** @var array<int, array<string, mixed>> $failedEvents */
            $failedEvents = [];
            foreach ($events as $event) {
                if (($event['retry_count'] ?? 0) < 3) {
                    $event['retry_count'] = ($event['retry_count'] ?? 0) + 1;
                    $failedEvents[] = $event;
                }
            }

            if ($this->batching && $failedEvents !== []) {
                $this->log('Re-queuing ' . count($failedEvents) . ' event(s) for retry');
                $this->queue = array_merge($failedEvents, $this->queue);
            }

            throw new \RuntimeException('Failed to send ' . count($events) . ' event(s): ' . $e->getMessage());
        }
    }

    /**
     * @param array<string, mixed> $event
     * @return array<string, mixed>
     */
    private function eventToPayload(array $event): array
    {
        // Note: timestamp is not sent - the API server generates it
        return [
            'event' => $event['event'],
            'actor' => $event['actor'],
            'user_ip' => $event['user_ip'],
            'metadata' => $event['metadata'],
        ];
    }

    private function getClient(): Client
    {
        if ($this->client === null) {
            $this->client = new Client([
                'headers' => [
                    'Content-Type' => 'application/json',
                    'X-API-Key' => $this->apiKey,
                    'User-Agent' => 'litesoc-php-sdk/' . self::VERSION,
                ],
            ]);
        }

        return $this->client;
    }

    /**
     * Set a custom HTTP client (for testing purposes only)
     *
     * @internal This method is for testing purposes only
     * @param Client $client The Guzzle HTTP client to use
     * @return void
     */
    public function setHttpClient(Client $client): void
    {
        $this->client = $client;
    }

    /**
     * Handle HTTP response errors and throw appropriate exceptions
     *
     * @throws AuthenticationException If API key is invalid (401)
     * @throws PlanRestrictedException If feature requires higher plan (403)
     * @throws NotFoundException If resource not found (404)
     * @throws ValidationException If request validation fails (400)
     * @throws RateLimitException If rate limit exceeded (429)
     * @throws LiteSOCException For other API errors
     */
    private function handleHttpError(RequestException $e): void
    {
        $response = $e->getResponse();
        $statusCode = $response?->getStatusCode() ?? 0;
        $body = $response?->getBody()?->getContents();
        $data = $body ? json_decode($body, true) : null;
        $message = $data['error'] ?? $e->getMessage();

        if ($statusCode === 400) {
            throw new ValidationException($message, $body, $e);
        }

        if ($statusCode === 401) {
            throw new AuthenticationException($message, $body, $e);
        }

        if ($statusCode === 403) {
            $requiredPlan = $data['required_plan'] ?? 'Pro or Enterprise';
            $upgradeHint = " Upgrade to {$requiredPlan} plan to access this feature.";
            throw new PlanRestrictedException($message . $upgradeHint, $requiredPlan, $body, $e);
        }

        if ($statusCode === 404) {
            throw new NotFoundException($message, $body, $e);
        }

        if ($statusCode === 429) {
            $retryAfter = isset($response) ? (int) $response->getHeaderLine('Retry-After') ?: null : null;
            throw new RateLimitException($message, $retryAfter, $body, $e);
        }

        throw new LiteSOCException($message, $statusCode, $body, $e);
    }

    private function handleError(string $context, \Throwable $error): void
    {
        if ($this->silent) {
            $this->log("Error in {$context}: " . $error->getMessage());
        } else {
            throw $error;
        }
    }

    private function log(string $message): void
    {
        if ($this->debug) {
            echo "[LiteSOC] {$message}\n";
        }
    }

    // ============================================
    // PLAN INFO METHODS
    // ============================================

    /**
     * Get plan information from the last API response
     *
     * Returns metadata parsed from response headers including:
     * - plan: Current plan name (e.g., "starter", "business", "enterprise")
     * - retentionDays: Data retention period in days
     * - cutoffDate: Earliest accessible data timestamp (ISO 8601)
     *
     * Note: This returns data from the most recent API call.
     * Call getAlerts() or getEvents() first to populate this data.
     *
     * @return ResponseMetadata|null Plan metadata or null if no API calls made yet
     */
    public function getPlanInfo(): ?ResponseMetadata
    {
        return $this->lastResponseMetadata;
    }

    /**
     * Check if plan information is available
     *
     * @return bool True if plan info has been populated from an API response
     */
    public function hasPlanInfo(): bool
    {
        return $this->lastResponseMetadata !== null && $this->lastResponseMetadata->hasPlanInfo();
    }

    // ============================================
    // MANAGEMENT API METHODS (Pro/Enterprise)
    // ============================================

    /**
     * Get alerts from the Management API
     *
     * Requires Pro or Enterprise plan.
     *
     * @param array{
     *     status?: string,
     *     severity?: string,
     *     alert_type?: string,
     *     limit?: int,
     *     offset?: int,
     * } $filters Optional filters:
     *     - status: Filter by status ('open', 'acknowledged', 'resolved', 'dismissed')
     *     - severity: Filter by severity ('low', 'medium', 'high', 'critical')
     *     - alert_type: Filter by type ('impossible_travel', 'brute_force_attack', 'geo_anomaly', etc.)
     *     - limit: Maximum number of alerts to return (default: 100, max: 500)
     *     - offset: Number of alerts to skip for pagination (default: 0)
     * @return array<string, mixed>
     * @throws AuthenticationException If API key is invalid
     * @throws PlanRestrictedException If plan doesn't support Management API
     * @throws ValidationException If request validation fails
     * @throws RateLimitException If rate limit exceeded
     * @throws LiteSOCException For other API errors
     */
    public function getAlerts(array $filters = []): array
    {
        // Apply default limit if not specified (matches lsoc_app default)
        if (!isset($filters['limit'])) {
            $filters['limit'] = 100;
        }
        $this->log('Fetching alerts');
        return $this->apiRequest('GET', '/alerts', $filters);
    }

    /**
     * Get a specific alert by ID
     *
     * Requires Pro or Enterprise plan.
     *
     * @param string $alertId The alert ID
     * @return array<string, mixed> The alert data
     * @throws AuthenticationException If API key is invalid
     * @throws PlanRestrictedException If plan doesn't support Management API
     * @throws NotFoundException If alert not found
     * @throws RateLimitException If rate limit exceeded
     * @throws LiteSOCException For other API errors
     */
    public function getAlert(string $alertId): array
    {
        $this->log('Fetching alert: ' . $alertId);
        return $this->apiRequest('GET', '/alerts/' . urlencode($alertId));
    }

    /**
     * Resolve an alert
     *
     * Requires Pro or Enterprise plan.
     *
     * @param string $alertId The alert ID to resolve
     * @param string $resolutionType Resolution type ('blocked_ip', 'reset_password', 
     *                               'contacted_user', 'false_positive', 'other')
     * @param string $notes Optional resolution notes
     * @param string $resolvedBy Optional identifier for who/what resolved the alert
     *                           (e.g., 'security-team', 'automation-v1'). Defaults to 'n8n-api'.
     * @return array<string, mixed> The updated alert
     * @throws AuthenticationException If API key is invalid
     * @throws PlanRestrictedException If plan doesn't support Management API
     * @throws NotFoundException If alert not found
     * @throws ValidationException If request validation fails
     * @throws RateLimitException If rate limit exceeded
     * @throws LiteSOCException For other API errors
     */
    public function resolveAlert(string $alertId, string $resolutionType, string $notes = '', string $resolvedBy = ''): array
    {
        $this->log('Resolving alert: ' . $alertId);
        $body = [
            'action' => 'resolve',
            'resolution_type' => $resolutionType,
        ];
        if ($notes !== '') {
            $body['internal_notes'] = $notes;
        }
        if ($resolvedBy !== '') {
            $body['resolved_by'] = $resolvedBy;
        }
        return $this->apiRequest('PATCH', '/alerts/' . urlencode($alertId), $body);
    }

    /**
     * Mark an alert as safe (false positive)
     *
     * Requires Pro or Enterprise plan.
     *
     * @param string $alertId The alert ID to mark as safe
     * @param string $notes Optional notes explaining why it's safe
     * @param string $resolvedBy Optional identifier for who/what marked the alert safe
     *                           (e.g., 'security-team', 'automation-v1'). Defaults to 'n8n-api'.
     * @return array<string, mixed> The updated alert
     * @throws AuthenticationException If API key is invalid
     * @throws PlanRestrictedException If plan doesn't support Management API
     * @throws NotFoundException If alert not found
     * @throws ValidationException If request validation fails
     * @throws RateLimitException If rate limit exceeded
     * @throws LiteSOCException For other API errors
     */
    public function markAlertSafe(string $alertId, string $notes = '', string $resolvedBy = ''): array
    {
        $this->log('Marking alert as safe: ' . $alertId);
        $body = [
            'action' => 'mark_safe',
        ];
        if ($notes !== '') {
            $body['internal_notes'] = $notes;
        }
        if ($resolvedBy !== '') {
            $body['resolved_by'] = $resolvedBy;
        }
        return $this->apiRequest('PATCH', '/alerts/' . urlencode($alertId), $body);
    }

    /**
     * Get events from the Management API
     *
     * Available to all plans. Free tier users will have some forensic
     * fields (network_intelligence, precise geolocation) redacted.
     *
     * @param int $limit Maximum number of events to return (default: 50, max: 100)
     * @param array{
     *     event_name?: string,
     *     actor_id?: string,
     *     severity?: string,
     *     offset?: int,
     * } $filters Optional filters:
     *     - event_name: Filter by event name (e.g., 'auth.login_failed')
     *     - actor_id: Filter by actor ID
     *     - severity: Filter by severity ('critical', 'warning', 'info')
     *     - offset: Number of events to skip for pagination (default: 0)
     * @return array<string, mixed>
     * @throws AuthenticationException If API key is invalid
     * @throws RateLimitException If rate limit exceeded
     * @throws LiteSOCException For other API errors
     */
    public function getEvents(int $limit = 50, array $filters = []): array
    {
        $this->log('Fetching events');
        return $this->apiRequest('GET', '/events', array_merge(['limit' => $limit], $filters));
    }

    /**
     * Get a specific event by ID
     *
     * Available to all plans. Free tier users will have some forensic
     * fields redacted.
     *
     * @param string $eventId The event ID
     * @return array<string, mixed> The event data
     * @throws AuthenticationException If API key is invalid
     * @throws NotFoundException If event not found
     * @throws RateLimitException If rate limit exceeded
     * @throws LiteSOCException For other API errors
     */
    public function getEvent(string $eventId): array
    {
        $this->log('Fetching event: ' . $eventId);
        return $this->apiRequest('GET', '/events/' . urlencode($eventId));
    }

    /**
     * Make an API request to the Management API
     *
     * @param string $method HTTP method
     * @param string $path API path
     * @param array<string, mixed> $data Request data (query params for GET, body for POST/PATCH)
     * @return array<string, mixed>
     */
    private function apiRequest(string $method, string $path, array $data = []): array
    {
        $client = $this->getClient();
        $url = $this->baseUrl . $path;

        try {
            $options = ['timeout' => $this->timeout];

            if ($method === 'GET' && !empty($data)) {
                $options['query'] = $data;
            } elseif (!empty($data)) {
                $options['json'] = $data;
            }

            $response = $client->request($method, $url, $options);

            // Parse plan/quota headers from response
            $this->lastResponseMetadata = ResponseMetadata::fromHeaders($response->getHeaders());

            $body = $response->getBody()->getContents();

            return json_decode($body, true) ?? [];
        } catch (RequestException $e) {
            $this->handleHttpError($e);
            // @codeCoverageIgnoreStart
            throw $e; // Never reached but required for static analysis
            // @codeCoverageIgnoreEnd
        }
    }
}
