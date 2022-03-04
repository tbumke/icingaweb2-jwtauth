<?php
/* Icinga Web 2 | (c) 2014 Icinga Development Team | GPLv2+ */

namespace Icinga\Authentication\User;

require __DIR__ . '/../../../vendor/autoload.php';

use Icinga\Application\Logger;
use Icinga\Data\ConfigObject;
use Icinga\User;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

/**
 * Test login with external authentication mechanism, e.g. Apache
 */
class ExternalBackend implements UserBackendInterface
{
    /**
     * Possible variables where to read the user from
     *
     * @var string[]
     */
    public static $remoteUserEnvvars = array('REMOTE_USER', 'REDIRECT_REMOTE_USER');

    /**
     * Possible variables where to read the JWT HTTP header from
     *
     * @var string
     */
    public static $jwtHttpHeaders = array('HTTP_X_AMZN_OIDC_DATA');

    /**
     * The name of this backend
     *
     * @var string
     */
    protected $name;

    /**
     * Regexp expression to strip values from a username
     *
     * @var string
     */
    protected $stripUsernameRegexp;

    /**
     * Create new authentication backend of type "external"
     *
     * @param ConfigObject $config
     */
    public function __construct(ConfigObject $config)
    {
        $this->stripUsernameRegexp = $config->get('strip_username_regexp');
    }

    /**
     * {@inheritdoc}
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * {@inheritdoc}
     */
    public function setName($name)
    {
        $this->name = $name;
        return $this;
    }

    /**
     * Get the remote user from environment or $_SERVER, if any
     *
     * @param   string  $variable   The name of the variable where to read the user from
     *
     * @return  string|null
     */
    public static function getRemoteUser($variable = 'REMOTE_USER')
    {
        if (in_array($variable, static::$jwtHttpHeaders)) {
            switch ($variable) {
                /* AWS ELB */
                case 'HTTP_X_AMZN_OIDC_DATA':
                    $jwtEncoded = getenv($variable);
                    if (empty($jwtEncoded) && (array_key_exists($variable, $_SERVER) && ! empty($_SERVER[$variable]))) {
                        $jwtEncoded = $_SERVER[$variable];
                    }
                    if (! empty($jwtEncoded)) {
                        try {
                            /* JWT format example: "header.payload.signature" */
                            $jwtHeader = explode('.', $jwtEncoded)[0];
                            $jwtHeaderDecoded = json_decode(base64_decode($jwtHeader));
                            /* Signer field example: "arn:aws:elasticloadbalancing:region-code:account-id:loadbalancer/app/load-balancer-name/load-balancer-id" */
                            $region = explode(':', $jwtHeaderDecoded->signer)[3];
                            $key = file_get_contents('https://public-keys.auth.elb.' . $region . '.amazonaws.com/' . $jwtHeaderDecoded->kid);
                            JWT::$leeway = 60;
                            $jwtPayloadDecoded = JWT::decode($jwtEncoded, new Key($key, $jwtHeaderDecoded->alg));
                            if (! empty($jwtPayloadDecoded->email)) {
                                return $jwtPayloadDecoded->email;
                            }
                        } catch (\Exception $e) {
                            Logger::error($e);
                        }
                    }
                    break;
            }
        } else {
            $username = getenv($variable);
            if (! empty($username)) {
                return $username;
            }

            if (array_key_exists($variable, $_SERVER) && ! empty($_SERVER[$variable])) {
                return $_SERVER[$variable];
            }
        }
    }

    /**
     * Get the remote user information from environment or $_SERVER, if any
     *
     * @return  array   Contains always two entries, the username and origin which may both set to null.
     */
    public static function getRemoteUserInformation()
    {
        foreach (static::$remoteUserEnvvars as $envVar) {
            $username = static::getRemoteUser($envVar);
            if ($username !== null) {
                return array($username, $envVar);
            }
        }
        foreach (static::$jwtHttpHeaders as $httpHeader) {
            $username = static::getRemoteUser($httpHeader);
            if ($username !== null) {
                return array($username, $httpHeader);
            }
        }

        return array(null, null);
    }

    /**
     * {@inheritdoc}
     */
    public function authenticate(User $user, $password = null)
    {
        list($username, $field) = static::getRemoteUserInformation();
        if ($username !== null) {
            $user->setExternalUserInformation($username, $field);

            if ($this->stripUsernameRegexp) {
                $stripped = @preg_replace($this->stripUsernameRegexp, '', $username);
                if ($stripped === false) {
                    Logger::error('Failed to strip external username. The configured regular expression is invalid.');
                    return false;
                }

                $username = $stripped;
            }

            $user->setUsername($username);
            return true;
        }

        return false;
    }
}
