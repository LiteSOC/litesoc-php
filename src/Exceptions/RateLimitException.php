<?php

declare(strict_types=1);

namespace LiteSOC\Exceptions;

/**
 * Exception thrown when API rate limit is exceeded (429 Too Many Requests)
 *
 * This indicates too many requests have been made in a given time period.
 */
class RateLimitException extends LiteSOCException
{
    private ?int $retryAfter;

    public function __construct(
        string $message = 'Rate limit exceeded',
        ?int $retryAfter = null,
        ?string $responseBody = null,
        ?\Throwable $previous = null
    ) {
        parent::__construct($message, 429, $responseBody, $previous);
        $this->retryAfter = $retryAfter;
    }

    /**
     * Get the number of seconds to wait before retrying
     */
    public function getRetryAfter(): ?int
    {
        return $this->retryAfter;
    }
}
