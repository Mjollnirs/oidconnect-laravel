<?php

namespace Furdarius\OIDConnect;

use Furdarius\OIDConnect\Exception\TokenRequestException;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\InvalidStateException;
use Laravel\Socialite\Two\ProviderInterface;
use Lcobucci\JWT\Parser;

class OIDConnectSocialiteProvider extends AbstractProvider implements ProviderInterface
{
    /**
     * The scopes being requested.
     *
     * @var array
     */
    protected $scopes = [
        'openid',
        'profile',
        'email',
        'roles'
    ];

    /**
     * The separating character for the requested scopes.
     *
     * @var string
     */
    protected $scopeSeparator = ' ';

    /**
     * JWT Token parser instance.
     *
     * @var \Lcobucci\JWT\Parser
     */
    protected $parser;
    /**
     * @var string
     */
    private $authUrl;
    /**
     * @var string
     */
    private $tokenUrl;

    /**
     * Create a new provider instance.
     *
     * @param  \Illuminate\Http\Request $request
     * @param  \Lcobucci\JWT\Parser     $parser
     * @param  string                   $clientId
     * @param  string                   $clientSecret
     * @param  string                   $redirectUrl
     * @param  string                   $authUrl
     * @param  string                   $tokenUrl
     */
    public function __construct(
        Request $request,
        Parser $parser,
        string $clientId,
        string $clientSecret,
        string $redirectUrl,
        string $authUrl,
        string $tokenUrl,
        array $scopes
    ) {
        parent::__construct($request, $clientId, $clientSecret, $redirectUrl);

        $this->parser = $parser;
        $this->authUrl = $authUrl;
        $this->tokenUrl = $tokenUrl;
        $this->scopes = array_merge($this->scopes, $scopes);
    }

    /**
     * {@inheritdoc}
     */
    public function user()
    {
        if ($this->hasInvalidState()) {
            throw new InvalidStateException;
        }

        $response = $this->getAccessTokenResponse($this->getCode());

        if (!empty($response['error'])) {
            throw new TokenRequestException($response['error']);
        }

        $token = $response['id_token'];

        $user = $this->mapUserToObject($this->getUserByToken($token));

        return $user->setToken($token)
            ->setAccessToken(Arr::get($response, 'access_token'))
            ->setRefreshToken(Arr::get($response, 'refresh_token'))
            ->setExpiresIn(Arr::get($response, 'expires_in'));
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        return (new User)->setRaw($user)->map([
            'id' => $user['sub'],
            'sub' => $user['sub'],
            'iss' => $user['iss'],
            'name' => $user['name'],
            'email' => $user['email'],
            'role' => $user['role'],
        ]);
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        /**
         * We cant get claims from Token interface, so call claims method implicitly
         * link: https://github.com/lcobucci/jwt/pull/186
         *
         * @var $plainToken \Lcobucci\JWT\Token\Plain
         */
        $plainToken = $this->parser->parse($token);

        $claims = $plainToken->getClaims();

        return [
            'sub' => $claims['sub'],
            'iss' => $claims['iss'],
            'name' => $claims['name'],
            'email' => $claims['email'],
            'role' => $claims['role'],
        ];
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenFields($code)
    {
        return [
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'code' => $code,
            'redirect_uri' => $this->redirectUrl,
            'grant_type' => 'authorization_code',
        ];
    }

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state)
    {
        return $this->with([
            'response_type' => 'code id_token',
            'response_mode' => 'form_post',
            'nonce' => md5(time()),
        ])->buildAuthUrlFromBase($this->authUrl, $state);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return $this->tokenUrl;
    }
}
