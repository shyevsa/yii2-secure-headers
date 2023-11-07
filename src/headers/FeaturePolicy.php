<?php

namespace shyevsa\security\headers;

use shyevsa\security\Dictionary;

class FeaturePolicy implements PolicyInterface
{
    private $directives;
    private $defaultDirectives = [
        'accelerometer' => Dictionary::POL_SELF,
        'ambient-light-sensor' => Dictionary::POL_SELF,
        'autoplay' => Dictionary::POL_SELF,
        'battery' => Dictionary::POL_SELF,
        'camera' => Dictionary::POL_SELF,
        'display-capture' => Dictionary::POL_SELF,
        'document-domain' => Dictionary::POL_SELF,
        'encrypted-media' => Dictionary::POL_SELF,
        'fullscreen' => Dictionary::POL_SELF,
        'geolocation' => Dictionary::POL_SELF,
        'gyroscope' => Dictionary::POL_SELF,
        'layout-animations' => Dictionary::POL_SELF,
        'magnetometer' => Dictionary::POL_SELF,
        'microphone' => Dictionary::POL_SELF,
        'midi' => Dictionary::POL_SELF,
        'oversized-images' => Dictionary::POL_SELF,
        'payment' => Dictionary::POL_SELF,
        'picture-in-picture' => "*",
        'publickey-credentials-get' => Dictionary::POL_SELF,
        'sync-xhr' => Dictionary::POL_SELF,
        'usb' => Dictionary::POL_SELF,
        'wake-lock' => Dictionary::POL_SELF,
        'xr-spatial-tracking' => Dictionary::POL_SELF
    ];

    public function __construct(?array $directives)
    {
        $this->directives = $directives;
    }

    public function getName(): string
    {
        return 'Feature-Policy';
    }

    public function getValue(): string
    {
        $result = '';
        $directivesArray = array_merge($this->defaultDirectives, $this->directives);

        foreach ($directivesArray as $directive => $value) {
            $result .= $directive . ' ' . $value . '; ';
        }

        return trim($result, '; ');
    }

    public function isValid(): bool
    {
        if ($this->directives === null) {
            return false;
        }

        return true;
    }
}
