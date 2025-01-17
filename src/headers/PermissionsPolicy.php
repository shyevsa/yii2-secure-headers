<?php

namespace hyperia\security\headers;

class PermissionsPolicy implements PolicyInterface
{
    private $directives;
    private $defaultDirectives = [
        'accelerometer' => "self",
        'ambient-light-sensor' => "self",
        'autoplay' => "self",
        'battery' => "self",
        'camera' => "self",
        'display-capture' => "self",
        'document-domain' => "self",
        'encrypted-media' => "self",
        'fullscreen' => "self",
        'geolocation' => "self",
        'gyroscope' => "self",
        'layout-animations' => "self",
        'magnetometer' => "self",
        'microphone' => "self",
        'midi' => "self",
        'oversized-images' => "self",
        'payment' => "self",
        'picture-in-picture' => "*",
        'publickey-credentials-get' => "self",
        'sync-xhr' => "self",
        'usb' => "self",
        'wake-lock' => "self",
        'xr-spatial-tracking' => "self"
    ];

    public function __construct(array $directives)
    {
        $this->directives = $directives;
    }

    public function getName(): string
    {
        return 'Permissions-Policy';
    }

    public function getValue(): string
    {
        $result = '';
        $directivesArray = array_merge($this->defaultDirectives, $this->directives);

        foreach ($directivesArray as $directive => $value) {
            if ($value === 'none') {
                $result .= $directive . '=(), ';
            } else {
                $result .= $directive . '=(' . $value . '), ';
            }

        }

        return trim($result, ', ');
    }

    public function isValid(): bool
    {
        return true;
    }
}
