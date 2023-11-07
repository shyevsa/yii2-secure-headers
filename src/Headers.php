<?php

namespace shyevsa\security;

use Exception;
use shyevsa\security\headers\ContentSecurityPolicy;
use shyevsa\security\headers\FeaturePolicy;
use shyevsa\security\headers\ReferrerPolicy;
use shyevsa\security\headers\StrictTransportSecurity;
use shyevsa\security\headers\XContentTypeOptions;
use shyevsa\security\headers\XFrameOptions;
use shyevsa\security\headers\XPoweredBy;
use shyevsa\security\headers\XssProtection;
use shyevsa\security\headers\ReportTo;
use shyevsa\security\headers\PermissionsPolicy;
use Yii;
use yii\base\BootstrapInterface;
use yii\base\Component;
use yii\base\Event;
use yii\web\HeaderCollection;
use yii\web\Response;

/**
 * Secure Headers Component
 *
 * @package shyevsa\security
 * @property string $nonce
 */
class Headers extends Component implements BootstrapInterface
{
    /**
     * Insecure request
     *
     * @access public
     * @var boolean
     */
    public $upgradeInsecureRequests = true;

    /**
     * Block disable mixed content
     *
     * @access public
     * @var boolean
     */
    public $blockAllMixedContent = true;

    /**
     * Strict Transport Security
     *
     * @access public
     * @var array
     */
    public $strictTransportSecurity = [];

    /**
     * X Frame Options
     *
     * @access public
     * @var string
     */
    public $xFrameOptions = 'DENY';

    /**
     * Content Security Policy directive
     *
     * @access public
     * @var array
     */
    public $cspDirectives = [];

    /**
     * Feature Policy directive
     *
     * @access public
     * @var array
     */
    public $featurePolicyDirectives = [];

    /**
     * Permissions Policy directive
     *
     * @access public
     * @var array
     */
    public $permissionsPolicyDirectives = [];

    /**
     * Powered By
     *
     * @access public
     * @var string
     */
    public $xPoweredBy = '';

    /**
     * Report URI
     *
     * @access public
     * @var string
     */
    public $reportUri = '';

    /**
     * Require Subresource Integrity for script
     *
     * @access public
     * @var bool
     */
    public $requireSriForScript = false;

    /**
     * Require Subresource Integrity for style
     *
     * @access public
     * @var bool
     */
    public $requireSriForStyle = false;

    /**
     * X-XSS-Protection
     *
     * @access public
     * @var boolean
     */
    public $xssProtection = true;

    /**
     * Referrer policy header
     *
     * @access public
     * @var string
     */
    public $referrerPolicy = 'no-referrer-when-downgrade';

    /**
     * X-Content-Type-Options
     *
     * @access public
     * @var boolean
     */
    public $contentTypeOptions = true;

    /**
     * Content-Security-Policy-Report-Only
     *
     * @access public
     * @var boolean
     */
    public $reportOnlyMode = false;

    /**
     * Report To policy
     *
     * @access public
     * @var array
     */
    public $reportTo = [];

    /**
     * Enable Nonce on Style
     *
     * @var bool
     */
    public $enableStyleNonce = false;

    /**
     * Enable Nonce on Script
     *
     * @var bool
     */
    public $enableScriptNonce = false;

    public array $cspConnectSrc = [Dictionary::POL_SELF];
    public array $cspFrameSrc = [Dictionary::POL_SELF];
    public array $cspImgSrc = [Dictionary::POL_SELF];
    public array $cspScriptSrc = [Dictionary::POL_SELF];
    public array $cspStyleSrc = [Dictionary::POL_SELF, "'unsafe-inline'"];
    public array $cspFormAction = [Dictionary::POL_SELF];

    public bool $enable = true;

    private $cspDirectivesMap = [
        'connect-src' => 'cspConnectSrc',
        'frame-src' => 'cspFrameSrc',
        'img-src' => 'cspImgSrc',
        'script-src' => 'cspScriptSrc',
        'style-src' => 'cspStyleSrc',
        'form-action' => 'cspFormAction',
    ];

    public function buildCspDirective($e = null): array
    {
        if ($this->enableScriptNonce) {
            $this->cspScriptSrc[] = "'nonce-{$this->nonce}'";
        }

        if ($this->enableStyleNonce) {
            $this->cspStyleSrc[] = "'nonce-{$this->nonce}'";
        }

        $directive = $this->cspDirectives;
        foreach ($this->cspDirectivesMap as $key => $value) {
            $this->{$value} = array_unique($this->{$value});
            $directive[$key] = implode(' ', $this->{$value});
        }

        return $this->cspDirectives = $directive;
    }

    public function buildHeaderPolicy(HeaderCollection $headers)
    {
        $headerPolicy = [
            new XPoweredBy($this->xPoweredBy),
            new XFrameOptions($this->xFrameOptions),
            new XContentTypeOptions($this->contentTypeOptions),
            new StrictTransportSecurity($this->strictTransportSecurity),
            new FeaturePolicy($this->featurePolicyDirectives),
            new PermissionsPolicy($this->permissionsPolicyDirectives),
            new ReferrerPolicy($this->referrerPolicy),
            new XssProtection($this->xssProtection, $this->reportUri),
            new ReportTo($this->reportTo),
            new ContentSecurityPolicy($this->cspDirectives, [
                'requireSriForScript' => $this->requireSriForScript,
                'requireSriForStyle' => $this->requireSriForStyle,
                'blockAllMixedContent' => $this->blockAllMixedContent,
                'upgradeInsecureRequests' => $this->upgradeInsecureRequests,
                'reportOnlyMode' => $this->reportOnlyMode
            ], $this->reportUri)
        ];

        foreach ($headerPolicy as $policy) {
            if ($policy->isValid() && !$headers->has($policy->getName())) {
                $headers->set($policy->getName(), $policy->getValue());
            }
        }
    }

    /**
     * Bootstrap (set up before request event)
     *
     * @access public
     * @param \yii\web\Application $app
     * @return void
     */
    public function bootstrap($app)
    {
        Event::on(Response::class, Response::EVENT_BEFORE_SEND, function () {
            $response = Yii::$app->response;
            if ($response instanceof Response) {
                $this->buildCspDirective();
                $this->buildHeaderPolicy($response->headers);
            }
        });
    }

    private string $nonceStr;

    /**
     * @return string
     * @throws Exception
     */
    public function getNonce(): string
    {
        if (!isset($this->nonceStr)) {
            $this->nonceStr = Yii::$app->security->generateRandomString();
        }
        return $this->nonceStr;
    }

    /**
     * @param string $nonce
     * @return Headers
     */
    public function setNonce(string $nonce)
    {
        $this->nonceStr = $nonce;
        return $this;
    }


    /**
     * @param string $value
     * @return $this
     */
    public function addFormAction(string $value)
    {
        $this->cspFormAction[] = $value;
        return $this;
    }

    /**
     * @param string $value
     * @return $this
     */
    public function addStyleSrc(string $value)
    {
        $this->cspStyleSrc[] = $value;
        return $this;
    }

    /**
     * @param string $value
     * @return $this
     */
    public function addScriptSrc(string $value)
    {
        $this->cspScriptSrc[] = $value;
        return $this;
    }

    /**
     * @param string $script
     */
    public function addScript(string $script)
    {
        $this->cspScriptSrc[] = self::genHash($script);
        return $this;
    }

    public function addStyle(string $style)
    {
        $this->cspStyleSrc[] = self::genHash($style);
        return $this;
    }

    public static function genHash(string $str)
    {
        $hash = base64_encode(hash('sha256', $str, true));
        return "'sha256-{$hash}'";
    }
}
