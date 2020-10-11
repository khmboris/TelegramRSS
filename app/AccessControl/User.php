<?php

namespace TelegramRSS\AccessControl;

class User
{

    public array $rpmLimit = [
        'media' => 15,
        'messages' => 15,
    ];
    public array $errorsLimit = [
        'media' => 0,
        'messages' => 0,
    ];
    public array $rpm = [
        'media' => 0,
        'messages' => 0,
    ];

    /** @var array of timestamps */
    private array $requests = [
        'media' => [],
        'messages' => [],
    ];

    public array $errors = [];

    private bool $permanentBan = false;
    private int $banLastDuration = 0;
    private int $banUntilTs = 0;
    private int $lastAccessTs = 0;

    private const RPM_TTL = '-1 minute';
    private const TTL = '-5 minutes';
    private const BAN_TTL = '-24 hours';

    private const BAN_DURATION_STEPS = [
        1 * 60,
        5 * 60,
        30 * 60,
        60 * 60,
        6 * 60 * 60,
        12 * 60 * 60,
        24 * 60 * 60,
    ];

    public function __construct(int $rpmLimit, int $mediaRpmLimit, int $errorsLimit, int $mediaErrorsLimit)
    {
        $this->rpmLimit = [
            'messages' => $rpmLimit,
            'media' => $mediaRpmLimit
        ];
        $this->errorsLimit = [
            'messages' => $errorsLimit,
            'media' => $mediaErrorsLimit
        ];

        if ($this->rpmLimit['messages'] === 0 && $this->rpmLimit['media'] === 0) {
            $this->permanentBan = true;
            $this->addError("Request from this IP forbidden", '');
        }
    }

    public function isOld(?int $now = null): bool
    {
        if ($now === null) {
            $now = time();
        }

        return $this->lastAccessTs < strtotime(static::TTL, $now)
            && $this->banUntilTs < strtotime(static::BAN_TTL)
        ;
    }

    public function addRequest(string $url, string $type): void
    {
        if ($this->isBanned()) {
            return;
        }

        if ($type !== 'media') {
            $type = 'messages';
        }

        $this->requests[$type][] = $this->lastAccessTs = time();
        $this->rpm[$type] = $this->getRPM($type);

        if ($this->rpmLimit[$type] === -1) {
            return;
        }

        if ($this->rpm[$type] > $this->rpmLimit[$type]) {
            $this->addError("Too many requests", $url);
        }
    }

    public function isBanned(): bool
    {
        return $this->permanentBan || $this->banUntilTs > time();
    }

    public function getBanDuration(): ?string
    {
        if (!$this->permanentBan) {
            $timeLeft = $this->banUntilTs - time();

            if ($timeLeft > 0) {
                return gmdate('H:i:s', $timeLeft);
            }
        }

        return null;
    }

    public function addBan(): void
    {
        if ($this->permanentBan) {
            return;
        }

        foreach (static::BAN_DURATION_STEPS as $duration) {
            if ($this->banLastDuration < $duration) {
                $this->banLastDuration = $duration;
                break;
            }
        }
        $this->banUntilTs = time() + $this->banLastDuration;

    }

    public function addError(string $reason, string $url): void
    {
        $this->errors[] = [
            'message' => $reason,
            'url' => $url,
            'ts' => time(),
        ];

        $this->trimByTtl($this->errors, static::RPM_TTL);

        if ($this->errorsLimit !== -1 && \count($this->errors) > $this->errorsLimit) {
            $this->addBan();
        }
    }

    private function getRPM(string $type): int
    {
        $this->trimByTtl($this->requests[$type], static::RPM_TTL);
        return \count($this->requests[$type]);
    }

    private function trimByTtl(array &$array, string $ttl, ?string $tsKey = 'ts'): array
    {
        $ttlTs = strtotime($ttl);

        $oldCount = 0;
        foreach ($array as $key => $item) {
            $ts = is_numeric($item) ? $item : $item[$tsKey];

            if ($ts > $ttlTs) {
                break;
            }

            $oldCount++;
        }

        if ($oldCount > 0) {
            array_splice($array, 0, $oldCount);
        }

        return $array;
    }


}