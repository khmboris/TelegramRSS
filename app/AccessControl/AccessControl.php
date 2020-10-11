<?php

namespace TelegramRSS\AccessControl;

use Swoole\Timer;
use TelegramRSS\Config;

class AccessControl
{
    /** @var User[] */
    private array $users = [];

    /** @var int Interval to remove old clients: 60 seconds */
    private const CLEANUP_INTERVAL_MS = 60*1000;
    private array $rpmLimit;
    private array $errorsLimit;
    private array $clientsSettings;

    public function __construct()
    {
        $this->rpmLimit['messages'] = (int) Config::getInstance()->get('access.rpm');
        $this->rpmLimit['media'] = (int) Config::getInstance()->get('access.media_rpm');

        $this->errorsLimit['messages'] = (int) Config::getInstance()->get('access.errors_limit');
        $this->errorsLimit['media'] = (int) Config::getInstance()->get('access.media_errors_limit');

        $this->clientsSettings = (array) Config::getInstance()->get('access.clients_settings');

        Timer::tick(static::CLEANUP_INTERVAL_MS, function () {
            $this->removeOldUsers();
        });
    }

    private function removeOldUsers(): void
    {
        $now = time();
        foreach ($this->users as $ip => $user) {
            if ($user->isOld($now)) {
                $this->removeUser($ip);
            }
        }
    }

    private function removeUser(string $ip): void
    {
        unset($this->users[$ip]);
    }

    public function getOrCreateUser($ip)
    {
        if (!isset($this->users[$ip])) {
            $this->users[$ip] = new User(
                $this->clientsSettings[$ip]['rpm'] ?? $this->rpmLimit['messages'],
                $this->clientsSettings[$ip]['media_rpm'] ?? $this->clientsSettings[$ip]['rpm'] ?? $this->rpmLimit['media'],
                $this->clientsSettings[$ip]['errors_limit'] ?? $this->errorsLimit['messages'],
                $this->clientsSettings[$ip]['media_errors_limit'] ?? $this->clientsSettings[$ip]['errors_limit'] ?? $this->errorsLimit['media'],
            );
        }

        return $this->users[$ip];
    }

}