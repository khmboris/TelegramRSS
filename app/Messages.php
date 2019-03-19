<?php

namespace TelegramRSS;


class Messages {
    private const TELEGRAM_URL = 'https://t.me/';

    private $list = [];
    private $telegramResponse;
    private $channelUrl;
    private $username;
    private $client;

    /**
     * Messages constructor.
     * @param $telegramResponse
     * @param Client $client
     */
    public function __construct($telegramResponse, Client $client) {
        $this->telegramResponse = $telegramResponse;
        $this->client = $client;
        $this->parseMessages();
    }

    private function parseMessages(): self {
        if ($messages = $this->telegramResponse->messages ?? []) {
            $size = count($messages);
            $chan = new \Co\Channel($size);
            foreach ($messages as $message) {
                go(
                    function () use ($chan, $message) {
                        $parsedMessage = [
                            'url' => $this->getChannelUrl() . $message->id,
                            'title' => null,
                            'description' => $message->message ?? '',
                            'media' => $this->getMediaInfo($message),
                            'preview' => $this->hasMedia($message) ? $this->getMediaUrl($message) . '/preview' : '',
                            'timestamp' => $message->date ?? '',
                        ];

                        $mime = $message->media->document->mime_type ?? '';
                        if (strpos($mime, 'video') !== false) {
                            $parsedMessage['title'] = '[Видео]';
                        }
                        $chan->push([$message->id => $parsedMessage]);
                    }
                );
            }

            for ($i = 0; $i < $size; $i++) {
                $element = $chan->pop();
                $key = array_key_first($element);
                $this->list[$key] = $element[$key];
            }
            krsort($this->list);

        }
        return $this;
    }

    private function hasMedia($message) {
        if (empty($message->media)) {
            return false;
        }
        if ($message->media->{'_'} === 'messageMediaWebPage') {
            return false;
        }
        return true;
    }

    private function getMediaInfo($message) {
        if (!$this->hasMedia($message)) {
            return [];
        }
        $info = $this->client->getMediaInfo($message);
        if (!empty($info->size) && !empty($info->mime)) {
            return [
                'url' => $this->getMediaUrl($message),
                'mime' => $info->mime,
                'size' => $info->size,
            ];
        }
    }

    private function getMediaUrl($message) {
        if (!$this->hasMedia($message)) {
            return false;
        }
        $url = Config::getInstance()->get('url');

        return "{$url}/media/{$this->username}/{$message->id}";
    }

    private function getChannelUrl() {
        if (!$this->channelUrl) {
            $this->username = $this->telegramResponse->chats[0]->username ?? '';
            if (!$this->username) {
                throw new \UnexpectedValueException('No channel username');
            }
            $this->channelUrl = static::TELEGRAM_URL . $this->username . '/';
        }
        return $this->channelUrl;
    }

    /**
     * @return array
     */
    public function get(): array {
        return $this->list;
    }

}