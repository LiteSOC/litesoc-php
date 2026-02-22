<?php

declare(strict_types=1);

namespace LiteSOC;

/**
 * Actor (user) information
 */
class Actor
{
    public function __construct(
        public readonly string $id,
        public readonly ?string $email = null,
    ) {
    }

    /**
     * Convert to array for API payload
     *
     * @return array{id: string, email: string|null}
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'email' => $this->email,
        ];
    }
}
