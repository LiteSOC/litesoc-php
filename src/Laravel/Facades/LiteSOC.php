<?php

declare(strict_types=1);

namespace LiteSOC\Laravel\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static void track(string $eventName, array $options = [])
 * @method static void trackLoginFailed(string $actorId, array $options = [])
 * @method static void trackLoginSuccess(string $actorId, array $options = [])
 * @method static void trackPrivilegeEscalation(string $actorId, array $options = [])
 * @method static void trackSensitiveAccess(string $actorId, string $resource, array $options = [])
 * @method static void trackBulkDelete(string $actorId, int $recordCount, array $options = [])
 * @method static void trackRoleChanged(string $actorId, string $oldRole, string $newRole, array $options = [])
 * @method static void trackAccessDenied(string $actorId, string $resource, array $options = [])
 * @method static void flush()
 * @method static int getQueueSize()
 * @method static void clearQueue()
 * @method static void shutdown()
 *
 * @see \LiteSOC\LiteSOC
 */
class LiteSOC extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'litesoc';
    }
}
