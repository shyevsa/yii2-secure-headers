<?php

namespace shyevsa\security\headers;

use shyevsa\security\Dictionary;

class ContentSecurityPolicy implements PolicyInterface
{
    private $directives;
    private $reportUri;
    private $requireSriForScript;
    private $requireSriForStyle;
    private $blockAllMixedContent;
    private $upgradeInsecureRequests;
    private $reportOnlyMode;
    private $defaultDirectives = [
        'connect-src' => Dictionary::POL_SELF,
        'font-src' => Dictionary::POL_SELF,
        'frame-src' => Dictionary::POL_SELF,
        'img-src' => "'self' data:",
        'manifest-src' => Dictionary::POL_SELF,
        'object-src' => Dictionary::POL_SELF,
        'prefetch-src' => Dictionary::POL_SELF,
        'script-src' => "'self' 'unsafe-inline'",
        'style-src' => "'self' 'unsafe-inline'",
        'media-src' => Dictionary::POL_SELF,
        'form-action' => Dictionary::POL_SELF,
        'worker-src' => Dictionary::POL_SELF,
    ];

    private $defaultCsp = [
        'default-src' => "'none'"
    ];

    public function __construct(?array $directives, array $params, string $reportUri)
    {
        $this->directives = $directives;
        $this->reportUri = $reportUri;
        $this->requireSriForScript = $params['requireSriForScript'] ?? false;
        $this->requireSriForStyle = $params['requireSriForStyle'] ?? false;
        $this->blockAllMixedContent = $params['blockAllMixedContent'] ?? false;
        $this->upgradeInsecureRequests = $params['upgradeInsecureRequests'] ?? false;
        $this->reportOnlyMode = $params['reportOnlyMode'] ?? false;
    }

    public function getName(): string
    {
        return $this->reportOnlyMode ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';
    }

    public function getValue(): string
    {
        $result = '';
        $cspDirectives = $this->buildPolicyArray();

        foreach ($cspDirectives as $directive => $value) {
            if (empty($value)) {
                continue;
            }
            $result .= $directive . ' ' . $value . '; ';
        }

        if ($this->blockAllMixedContent) {
            $result .= 'block-all-mixed-content; ';
        }

        if ($this->upgradeInsecureRequests) {
            $result .= 'upgrade-insecure-requests; ';
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

    private function getCspReportUri(): array
    {
        $report = [];
        if (!empty($this->reportUri)) {
            $report = [
                'report-uri' => $this->reportUri
            ];
        }

        return $report;
    }

    private function getCspSubresourceIntegrity(): array
    {
        $result = [];

        if ($this->requireSriForScript) {
            $values[] = 'script';
        }

        if ($this->requireSriForStyle) {
            $values[] = 'style';
        }

        if (!empty($values)) {
            $result = [
                'require-sri-for' => implode(' ', $values)
            ];
        }

        return $result;
    }

    private function buildPolicyArray(): array
    {
        return array_merge(
            $this->defaultCsp,
            $this->defaultDirectives,
            $this->directives,
            $this->getCspSubresourceIntegrity(),
            $this->getCspReportUri()
        );
    }
}
