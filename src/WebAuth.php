<?php
namespace CarloNicora\Minimalism\Services\WebAuth;

use CarloNicora\Minimalism\Abstracts\AbstractService;
use CarloNicora\Minimalism\ApiCaller\Commands\ApiCallerCommand;
use CarloNicora\Minimalism\ApiCaller\Data\ApiRequest;
use CarloNicora\Minimalism\ApiCaller\Enums\Verbs;
use CarloNicora\Minimalism\Enums\HttpCode;
use CarloNicora\Minimalism\Services\Path;
use Exception;

class WebAuth extends AbstractService
{
    /** @var string|null  */
    private ?string $state=null;

    /** @var string|null  */
    private ?string $token=null;


    /** @var string|null  */
    private ?string $pageBeforeLogin=null;

    /**
     * @param Path $path
     * @param string $MINIMALISM_SERVICE_WEBAUTH_URL
     * @param string $MINIMALISM_SERVICE_WEBAUTH_CLIENT_ID
     * @param string|null $MINIMALISM_SERVICE_WEBAUTH_HOSTNAME
     */
    public function __construct(
        private readonly Path $path,
        private string $MINIMALISM_SERVICE_WEBAUTH_URL,
        private readonly string $MINIMALISM_SERVICE_WEBAUTH_CLIENT_ID,
        private readonly ?string $MINIMALISM_SERVICE_WEBAUTH_HOSTNAME=null,
    )
    {
    }

    /**
     * @return void
     */
    public function initialise(
    ): void
    {
        if(!str_ends_with($this->MINIMALISM_SERVICE_WEBAUTH_URL, '/')){
            $this->MINIMALISM_SERVICE_WEBAUTH_URL .= '/';
        }

        if (array_key_exists('token', $_SESSION) && $_SESSION['token'] !== null) {
            $this->token = $_SESSION['token'];
        } elseif (array_key_exists('token', $_COOKIE) && $_COOKIE['token'] !== null) {
            $this->token = $_COOKIE['token'];
        }

        if (array_key_exists('pageBeforeLogin', $_SESSION)){
            $this->pageBeforeLogin = $_SESSION['pageBeforeLogin'];
        }

        $this->state = $_SESSION['authState'] ?? null;
    }

    /**
     * @return void
     */
    public function destroy(
    ): void
    {
        if ($this->token !== null) {
            if (!array_key_exists('token', $_COOKIE) || $_COOKIE['token'] === null) {
                /** @noinspection SummerTimeUnsafeTimeManipulationInspection */
                setcookie('token', $this->token, time() + (60 * 60 * 24 * 365), "/", ini_get('session.cookie_domain'), ini_get('session.cookie_secure'), ini_get('session.cookie_httponly'));
            }

            $_SESSION['token'] = $this->token;
        }

        $this->token = null;

        if ($this->state !== null){
            $_SESSION['authState'] = $this->state;
        }

        if ($this->pageBeforeLogin !== null){
            $_SESSION['pageBeforeLogin'] = $this->pageBeforeLogin;
        }
    }

    /**
     * @return string|null
     */
    public function getToken(
    ): ?string
    {
        return $this->token;
    }

    /**
     * @return string
     * @throws Exception
     */
    private function getState(
    ): string
    {
        if ($this->state === null) {
            $this->state = bin2hex(random_bytes(5));
        }

        return $this->state;
    }

    /**
     * @param string $code
     * @return void
     * @throws Exception
     */
    public function retrieveToken(
        string $code,
    ): void
    {
        $response = ApiCallerCommand::call(
            request: new ApiRequest(
                verb: Verbs::Post,
                endpoint: 'token',
                payload: [
                    'grant_type' => 'authorization_code',
                    'code' => $code,
                    'client_id' => $this->MINIMALISM_SERVICE_WEBAUTH_CLIENT_ID,
                ],
            ),
            server: $this->MINIMALISM_SERVICE_WEBAUTH_URL,
            hostName: $this->MINIMALISM_SERVICE_WEBAUTH_HOSTNAME,
        );

        if ($response->getHttpCode() === HttpCode::Created){
            $data = json_decode($response->getRawResponse(), true, 512, JSON_THROW_ON_ERROR);
            $this->token = $data['access_token'];
        }
    }

    /**
     * @param string $state
     * @return bool
     */
    public function validateState(
        string $state,
    ): bool
    {
        if ($this->state === $state){
            $this->state = null;
            unset($_SESSION['authState']);
            return true;
        }

        return false;
    }

    /**
     * @return never
     */
    public function logout(
    ): never
    {
        $this->token = null;
        setcookie('token', '', time() - 3600, ini_get('session.cookie_path'), ini_get('session.cookie_domain'), ini_get('session.cookie_secure'), ini_get('session.cookie_httponly'));
        unset( $_SESSION['userId'],$_SESSION['token'],$_COOKIE['token']);
        /** @noinspection UnusedFunctionResultInspection */
        $this->redirectToPreviousPage();
    }

    /**
     * @return never
     * @throws Exception
     */
    public function redirectToAuth(
    ): never
    {
        $this->pageBeforeLogin = substr($this->path->getUrl(), 0, -1) . $_SERVER['REQUEST_URI'];

        $url = $this->MINIMALISM_SERVICE_WEBAUTH_HOSTNAME !== null
            ? explode('/', $this->MINIMALISM_SERVICE_WEBAUTH_URL, 1)[0] . '://' . $this->MINIMALISM_SERVICE_WEBAUTH_HOSTNAME . '/'
            : $this->MINIMALISM_SERVICE_WEBAUTH_URL;

        $url .= 'auth' .
            '?client_id=' . $this->MINIMALISM_SERVICE_WEBAUTH_CLIENT_ID .
            '&state=' . $this->getState();

        header('Location:' . $url);
        exit;
    }

    /**
     * @return never
     */
    public function redirectToPreviousPage(
    ): never
    {
        $url = $this->pageBeforeLogin ?? $this->path->getUrl();
        $this->pageBeforeLogin = null;

        header('Location:' . $url);
        exit;
    }
}