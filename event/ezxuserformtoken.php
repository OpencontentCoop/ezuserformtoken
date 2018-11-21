<?php

class ezxUserFormToken
{
    const FORM_FIELD = 'ezxuserform_token';

    const REPLACE_KEY = '@$ezxUserFormToken@';

    /**
     * @var string|null
     */
    static protected $secret;

    /**
     * @var string
     */
    static protected $intention = 'legacy';

    /**
     * @var string
     */
    static protected $formField = self::FORM_FIELD;

    /**
     * @var string
     */
    static protected $token;

    /**
     * @var bool
     */
    static protected $isEnabled = true;

    /**
     * @var eZURI
     */
    static protected $currentUri;

    /**
     * @return string
     */
    static protected function getSecret()
    {
        if (self::$secret === null) {
            self::$secret = eZINI::instance('site.ini')->variable('HTMLForms', 'Secret');
        }

        return self::$secret;
    }

    /**
     * @param string $secret
     */
    static public function setSecret($secret)
    {
        self::$secret = $secret;
    }

    /**
     * @return string
     */
    static protected function getIntention()
    {
        return self::$intention;
    }

    /**
     * @param string $intention
     */
    static public function setIntention($intention)
    {
        self::$intention = $intention;
    }

    /**
     * @return string
     */
    static protected function getFormField()
    {
        return self::$formField;
    }

    /**
     * @param string $formField
     */
    static public function setFormField($formField)
    {
        self::$formField = $formField;
    }

    /**
     * @param eZURI $uri
     * @return bool
     * @throws Exception
     */
    static public function input(eZURI $uri)
    {
        self::$currentUri = $uri;

        if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] !== 'POST' && empty($_POST)) {
            eZDebugSetting::writeDebug('ezuserformtoken', 'Input not protected (not POST)', __METHOD__);
            return false;
        }

        if (!self::shouldProtectInput()) {
            eZDebugSetting::writeDebug('ezuserformtoken', 'Input not protected (not logged in user)', __METHOD__);
            return false;
        }

        if (!empty($_POST[self::getFormField()])) {
            $token = $_POST[self::getFormField()];
        } else if (!empty($_SERVER['HTTP_X_CSRF_TOKEN'])) {
            $token = $_SERVER['HTTP_X_CSRF_TOKEN'];
        } else {
            throw new Exception('Missing form token from Request', 404);
        }

        if ($token !== $_COOKIE[self::getFormField()])
            throw new Exception('Wrong form token found in Request!', 404);

        eZDebugSetting::writeDebug('ezuserformtoken', 'Input validated, token verified and was correct', __METHOD__);
        self::removeCookie();

        return true;
    }

    /**
     * response/output event filter
     * Appends tokens to  POST forms if user is logged in.
     *
     * @param string $templateResult ByRef
     * @param bool $filterForms For use when the output has already been filtered, but not for the whole layout.
     *
     * @return mixed|string
     */
    static public function output($templateResult, $filterForms = true)
    {
        if (!self::hasTargetToProtect($templateResult)) {
            eZDebugSetting::writeDebug('ezuserformtoken', 'Output not protected (target to protect not found)', __METHOD__);
            return $templateResult;
        }

        // We only rewrite pages served with an html/xhtml content type
        $sentHeaders = headers_list();
        foreach ($sentHeaders as $header) {
            // Search for a content-type header that is NOT HTML
            // Note the Content-Type header will not be included in
            // headers_list() unless it has been explicitly set from PHP.
            if (stripos($header, 'Content-Type:') === 0 &&
                strpos($header, 'text/html') === false &&
                strpos($header, 'application/xhtml+xml') === false) {
                eZDebugSetting::writeDebug('ezuserformtoken', 'Output not protected (Content-Type is not html/xhtml)', __METHOD__);
                return $templateResult;
            }
        }

        $token = self::getToken();
        $field = self::getFormField();
        $replaceKey = self::REPLACE_KEY;

        eZDebugSetting::writeDebug('ezuserformtoken', 'Output protected (all forms will be modified)', __METHOD__);

        // If document has head tag, insert in a html5 valid and semi standard way
        if (strpos($templateResult, '<head>') !== false) {
            $templateResult = str_replace(
                '<head>',
                "<head>\n"
                . "<meta name=\"csrf-param\" content=\"{$field}\" />\n"
                . "<meta name=\"csrf-token\" id=\"{$field}_js\" title=\"{$token}\" content=\"{$token}\" />\n",
                $templateResult
            );
        } // else fallback to hidden span inside body
        else {
            $templateResult = preg_replace(
                '/(<body[^>]*>)/i',
                '\\1' . "\n<span style='display:none;' id=\"{$field}_js\" title=\"{$token}\"></span>\n",
                $templateResult
            );
        }

        self::setCookie($token);

        if ($filterForms) {
            $templateResult = preg_replace(
                '/(<form\W[^>]*\bmethod=(\'|"|)POST(\'|"|)\b[^>]*>)/i',
                '\\1' . "\n<input type=\"hidden\" name=\"{$field}\" value=\"{$token}\" />\n",
                $templateResult
            );
        }

        return str_replace($replaceKey, $token, $templateResult);
    }

    protected static function setCookie($token)
    {
        $ini = eZINI::instance();
        $name = self::getFormField();
        $value = $token;
        $expire = $ini->hasVariable('UserFormToken', 'CookieExpiry') ? $ini->variable('UserFormToken', 'CookieExpiry') : time() + 60 * 60 * 24;
        $path = $ini->hasVariable('UserFormToken', 'CookiePath') ? $ini->variable('UserFormToken', 'CookiePath') : "";
        $domain = $ini->hasVariable('UserFormToken', 'CookieDomain') ? $ini->variable('UserFormToken', 'CookieDomain') : "";
        $secure = $ini->hasVariable('UserFormToken', 'CookieSecure') ? $ini->variable('UserFormToken', 'CookieSecure') : false;
        $httponly = $ini->hasVariable('UserFormToken', 'CookieHttponly') && $ini->variable('UserFormToken', 'CookieHttponly') == 'true' ? true : false;

        setcookie($name, $value, $expire, $path, $domain, $secure, $httponly);
    }

    protected static function removeCookie()
    {
        $name = self::getFormField();
        setcookie($name, "", time() - 3600);
    }


    /**
     * Gets the user token
     *
     * @return string|null
     */
    static public function getToken()
    {
        if (self::$token === null) {
            $token = bin2hex(openssl_random_pseudo_bytes(16));
            self::$token = sha1(self::getSecret() . self::getIntention() . $token);
        }

        return self::$token;
    }

    /**
     * Enables/Disables CSRF protection.
     *
     * @param bool $isEnabled
     */
    static public function setIsEnabled($isEnabled)
    {
        self::$isEnabled = (bool)$isEnabled;
    }

    static public function isEnabled()
    {
        return (bool)self::$isEnabled;
    }

    /**
     * Figures out if current user should be protected in user module
     *
     * @return bool
     */
    static protected function shouldProtectInput()
    {
        if (!self::$isEnabled)
            return false;

        if (eZUser::isCurrentUserRegistered())
            return false;

        if (self::$currentUri instanceof eZURI) {
            self::$currentUri->toBeginning();
            $protectModuleList = (array)eZINI::instance()->variable('UserFormToken', 'ProtectModules');
            foreach ($protectModuleList as $protectModule) {
                if (self::$currentUri->attribute('element') == $protectModule) {
                    self::$currentUri->toBeginning();
                    return true;
                }
            }
        }

        return false;
    }

    static protected function hasTargetToProtect($templateResult)
    {
        if (!self::$isEnabled)
            return false;

        if (eZUser::isCurrentUserRegistered())
            return false;

        $protectModuleList = (array)eZINI::instance()->variable('UserFormToken', 'ProtectModules');
        preg_match('/(<form\W[^>]*\bmethod=(\'|"|)POST(\'|"|)\b[^>]*>)/i', $templateResult, $matches);
        foreach ($matches as $match) {
            foreach ($protectModuleList as $protectModule) {
                if (strpos($match, $protectModule) !== false) {
                    return true;
                }
            }
        }

        return false;
    }
}

