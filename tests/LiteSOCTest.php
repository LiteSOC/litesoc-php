<?php

declare(strict_types=1);

namespace LiteSOC\Tests;

use PHPUnit\Framework\TestCase;
use LiteSOC\LiteSOC;
use LiteSOC\Actor;
use LiteSOC\EventType;
use LiteSOC\EventSeverity;

class LiteSOCTest extends TestCase
{
    private LiteSOC $sdk;

    protected function setUp(): void
    {
        $this->sdk = new LiteSOC('test-key', [
            'batching' => true,
            'debug' => false,
        ]);
    }

    protected function tearDown(): void
    {
        $this->sdk->clearQueue();
    }

    public function testInitWithApiKey(): void
    {
        $sdk = new LiteSOC('test-key');
        $this->assertInstanceOf(LiteSOC::class, $sdk);
    }

    public function testInitWithoutApiKeyThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new LiteSOC('');
    }

    public function testInitWithCustomOptions(): void
    {
        $sdk = new LiteSOC('test-key', [
            'endpoint' => 'https://custom.endpoint.com',
            'batching' => false,
            'batch_size' => 20,
            'flush_interval' => 10.0,
            'debug' => true,
            'silent' => false,
            'timeout' => 60.0,
        ]);
        $this->assertInstanceOf(LiteSOC::class, $sdk);
    }

    public function testTrackBasicEvent(): void
    {
        $this->sdk->track('auth.login_failed', ['actor_id' => 'user_123']);
        $this->assertEquals(1, $this->sdk->getQueueSize());
    }

    public function testTrackWithActorId(): void
    {
        $this->sdk->track('auth.login_success', [
            'actor_id' => 'user_123',
            'actor_email' => 'test@example.com'
        ]);
        $this->assertEquals(1, $this->sdk->getQueueSize());
    }

    public function testTrackWithMetadata(): void
    {
        $this->sdk->track('auth.login_failed', [
            'actor_id' => 'user_123',
            'metadata' => ['reason' => 'invalid_password', 'attempts' => 3]
        ]);
        $this->assertEquals(1, $this->sdk->getQueueSize());
    }

    public function testTrackWithSeverity(): void
    {
        $this->sdk->track('security.suspicious_activity', [
            'actor_id' => 'user_123',
            'severity' => EventSeverity::CRITICAL
        ]);
        $this->assertEquals(1, $this->sdk->getQueueSize());
    }

    public function testTrackMultipleEvents(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $this->sdk->track('auth.login_failed', ['actor_id' => "user_$i"]);
        }
        $this->assertEquals(5, $this->sdk->getQueueSize());
    }

    public function testTrackLoginFailed(): void
    {
        $this->sdk->trackLoginFailed('user_123', ['user_ip' => '192.168.1.1']);
        $this->assertEquals(1, $this->sdk->getQueueSize());
    }

    public function testTrackLoginSuccess(): void
    {
        $this->sdk->trackLoginSuccess('user_123', ['user_ip' => '192.168.1.1']);
        $this->assertEquals(1, $this->sdk->getQueueSize());
    }

    public function testTrackPrivilegeEscalation(): void
    {
        $this->sdk->trackPrivilegeEscalation('admin_user', ['user_ip' => '192.168.1.1']);
        $this->assertEquals(1, $this->sdk->getQueueSize());
    }

    public function testTrackSensitiveAccess(): void
    {
        $this->sdk->trackSensitiveAccess('user_123', 'pii_table', ['user_ip' => '192.168.1.1']);
        $this->assertEquals(1, $this->sdk->getQueueSize());
    }

    public function testTrackBulkDelete(): void
    {
        $this->sdk->trackBulkDelete('admin_user', 500, ['user_ip' => '192.168.1.1']);
        $this->assertEquals(1, $this->sdk->getQueueSize());
    }

    public function testTrackRoleChanged(): void
    {
        $this->sdk->trackRoleChanged('user_123', 'viewer', 'admin');
        $this->assertEquals(1, $this->sdk->getQueueSize());
    }

    public function testTrackAccessDenied(): void
    {
        $this->sdk->trackAccessDenied('user_123', '/admin/settings');
        $this->assertEquals(1, $this->sdk->getQueueSize());
    }

    public function testGetQueueSize(): void
    {
        $this->assertEquals(0, $this->sdk->getQueueSize());
        $this->sdk->track('auth.login_failed', ['actor_id' => 'user_123']);
        $this->assertEquals(1, $this->sdk->getQueueSize());
    }

    public function testClearQueue(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $this->sdk->track('auth.login_failed', ['actor_id' => "user_$i"]);
        }
        $this->assertEquals(5, $this->sdk->getQueueSize());
        
        $this->sdk->clearQueue();
        $this->assertEquals(0, $this->sdk->getQueueSize());
    }

    public function testActorToArray(): void
    {
        $actor = new Actor('user_123', 'test@example.com');
        $result = $actor->toArray();
        
        $this->assertEquals('user_123', $result['id']);
        $this->assertEquals('test@example.com', $result['email']);
    }

    public function testActorWithoutEmail(): void
    {
        $actor = new Actor('user_123');
        $result = $actor->toArray();
        
        $this->assertEquals('user_123', $result['id']);
        $this->assertNull($result['email']);
    }

    public function testEventTypeConstants(): void
    {
        $this->assertEquals('auth.login_failed', EventType::AUTH_LOGIN_FAILED);
        $this->assertEquals('auth.login_success', EventType::AUTH_LOGIN_SUCCESS);
        $this->assertEquals('admin.privilege_escalation', EventType::ADMIN_PRIVILEGE_ESCALATION);
    }

    public function testEventSeverityConstants(): void
    {
        $this->assertEquals('low', EventSeverity::LOW);
        $this->assertEquals('medium', EventSeverity::MEDIUM);
        $this->assertEquals('high', EventSeverity::HIGH);
        $this->assertEquals('critical', EventSeverity::CRITICAL);
    }
}
