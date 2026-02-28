<?php

declare(strict_types=1);

namespace LiteSOC\Exceptions;

/**
 * Base exception for all LiteSOC SDK errors
 */
class LiteSOCException extends \RuntimeException
{
    protected int $statusCode;
    protected ?string $responseBody;

    public function __construct(
        string $message,
        int $statusCode = 0,
        ?string $responseBody = null,
        ?\Throwable $previous = null
    ) {
        parent::__construct($message, $statusCode, $previous);
        $this->statusCode = $statusCode;
        $this->responseBody = $responseBody;
    }

    /**
     * Get the HTTP status code
     */
    public function getStatusCode(): int
    {
        return $this->statusCode;
    }

    /**
     * Get the raw response body
     */
    public function getResponseBody(): ?string
    {
        return $this->responseBody;
    }
}
