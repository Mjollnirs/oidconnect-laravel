<?php
/**
 * Created by PhpStorm.
 * User: i
 * Date: 2018/7/16
 * Time: 10:29
 */

namespace Furdarius\OIDConnect;

use Laravel\Socialite\Two\User as BaseUser;

class User extends BaseUser
{
    public $accessToken;
    public $role;
    public $permission;

    public function setAccessToken($token){
        $this->accessToken = $token;

        return $this;
    }

    public function getAccessToken(){
        return $this->accessToken;
    }

    public function getRoles(){
        return $this->role;
    }
}
