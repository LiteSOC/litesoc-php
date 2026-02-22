<?php

declare(strict_types=1);

namespace LiteSOC;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;

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
 * ```
 */
class LiteSOC
{
    public const VERSION = '1.0.0';

    private string $apiKey;
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
     * Initialize the LiteSOC SDK
     *
     * @param string $apiKey Your LiteSOC API key (required)
     * @param array{
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
        $this->endpoint = $options['endpoint'] ?? 'https://www.litesoc.io/api/v1/collect';
        $this->batching = $options['batching'] ?? true;
        $this->batchSize = $options['batch_size'] ?? 10;
        $this->flushInterval = $options['flush_interval'] ?? 5.0;
        $this->debug = $options['debug'] ?? false;
        $this->silent = $options['silent'] ?? true;
        $this->timeout = $options['timeout'] ?? 30.0;

        $this->log('Initialized with endpoint: ' . $this->endpoint);
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
                        'id' => $options['actor']['id'] ?? null,
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

            if (isset($options['severity'])) {
                $metadata['_severity'] = $options['severity'];
            }

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
     * Track a privilege escalation event (critical severity)
     *
     * @param string $actorId User ID
     * @param array{actor_email?: string, user_ip?: string, metadata?: array<string, mixed>} $options
     */
    public function trackPrivilegeEscalation(string $actorId, array $options = []): void
    {
        $this->track('admin.privilege_escalation', array_merge([
            'actor_id' => $actorId,
            'severity' => EventSeverity::CRITICAL,
        ], $options));
    }

    /**
     * Track a sensitive data access event (high severity)
     *
     * @param string $actorId User ID
     * @param string $resource Resource accessed
     * @param array{actor_email?: string, user_ip?: string, metadata?: array<string, mixed>} $options
     */
    public function trackSensitiveAccess(string $actorId, string $resource, array $options = []): void
    {
        $metadata = $options['metadata'] ?? [];
        $metadata['resource'] = $resource;

        $this->track('data.sensitive_access', array_merge([
            'actor_id' => $actorId,
            'severity' => EventSeverity::HIGH,
            'metadata' => $metadata,
        ], $options));
    }

    /**
     * Track a bulk delete event (high severity)
     *
     * @param string $actorId User ID
     * @param int $recordCount Number of records deleted
     * @param array{actor_email?: string, user_ip?: string, metadata?: array<string, mixed>} $options
     */
    public function trackBulkDelete(string $actorId, int $recordCount, array $options = []): void
    {
        $metadata = $options['metadata'] ?? [];
        $metadata['records_deleted'] = $recordCount;

        $this->track('data.bulk_delete', array_merge([
            'actor_id' => $actorId,
            'severity' => EventSeverity::HIGH,
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
     * @param array<int, array<string, mixed>> $events
     */
    private function sendEvents(array $events): void
    {
        if (empty($events)) {
            return;
        }

        $client = $this->getClient();

        try {
            // Single event or batch
            $isBatch = count($events) > 1;

            if ($isBatch) {
                $payload = ['events' => array_map([$this, 'eventToPayload'], $events)];
            } else {
                $payload = $this->eventToPayload($events[0]);
            }

            $response = $client->post($this->endpoint, [
                'json' => $payload,
                'timeout' => $this->timeout,
            ]);

            $result = json_decode($response->getBody()->getContents(), true);

            if ($result['success'] ?? false) {
                $acceptedMsg = $isBatch ? " ({$result['events_accepted']} accepted)" : '';
                $this->log('Successfully sent ' . count($events) . ' event(s)' . $acceptedMsg);
            } else {
                throw new \RuntimeException($result['error'] ?? 'Unknown API error');
            }
        } catch (GuzzleException $e) {
            // Re-queue events for retry
            $retryable = array_filter($events, fn($ev) => ($ev['retry_count'] ?? 0) < 3);

            if (!empty($retryable) && $this->batching) {
                $this->log('Re-queuing ' . count($retryable) . ' events for retry');
                foreach ($retryable as &$event) {
                    $event['retry_count'] = ($event['retry_count'] ?? 0) + 1;
                }
                $this->queue = array_merge($retryable, $this->queue);
            }

            throw $e;
        }
    }

    /**
     * @param array<string, mixed> $event
     * @return array<string, mixed>
     */
    private function eventToPayload(array $event): array
    {
        return [
            'event' => $event['event'],
            'actor' => $event['actor'],
            'user_ip' => $event['user_ip'],
            'metadata' => $event['metadata'],
            'timestamp' => $event['timestamp'],
        ];
    }

    private function getClient(): Client
    {
        if ($this->client === null) {
            $this->client = new Client([
                'headers' => [
                    'Content-Type' => 'application/json',
                    'Authorization' => 'Bearer ' . $this->apiKey,
                    'User-Agent' => 'litesoc-php/' . self::VERSION,
                ],
            ]);
        }

        return $this->client;
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
}
