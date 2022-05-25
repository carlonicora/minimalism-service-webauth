<?php
namespace CarloNicora\Minimalism\Services\WebAuth\Models;

use CarloNicora\Minimalism\Abstracts\AbstractModel;
use CarloNicora\Minimalism\Factories\MinimalismFactories;
use Exception;
use CarloNicora\Minimalism\Services\WebAuth\WebAuth;

class AuthReturn extends AbstractModel
{
    /** @var WebAuth  */
    private WebAuth $webAuth;

    public function __construct(
        MinimalismFactories $minimalismFactories,
        ?string $function = null,
    )
    {
        parent::__construct($minimalismFactories, $function);

        $this->webAuth = $minimalismFactories->getServiceFactory()->create(WebAuth::class);
    }

    /**
     * @param string $code
     * @return never
     * @throws Exception
     */
    public function get(
        string $code,
    ): never
    {
        $this->webAuth->retrieveToken($code);
        /** @noinspection UnusedFunctionResultInspection */
        $this->webAuth->redirectToPreviousPage();
    }
}