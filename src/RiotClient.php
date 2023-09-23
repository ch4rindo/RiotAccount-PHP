<?php

declare(strict_types=1);

namespace charindo\RiotAccount;

use charindo\RiotAccount\constants\ExceptionErrorCode;
use charindo\RiotAccount\exception\AuthenticationException;
use charindo\RiotAccount\exception\ValidationException;
use GuzzleHttp\Client;
use GuzzleHttp\RequestOptions;

final class RiotClient{

	private Client $client;

	private string $password = "";
	private bool $loggedIn = false;

	public function __construct(){
		$this->client = new Client([
			RequestOptions::COOKIES => true,
			RequestOptions::HEADERS => [
				"User-Agent" => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36"
			],
			RequestOptions::VERIFY => false,
			RequestOptions::HTTP_ERRORS => false,
			RequestOptions::DEBUG => false,
			RequestOptions::ALLOW_REDIRECTS => ["max" => 10],
			"curl" => [
				CURLOPT_SSLVERSION => CURL_SSLVERSION_TLSv1_3,
				CURLOPT_SSL_CIPHER_LIST => "ECDHE+AESGCM"
			]
		]);

	}

	public function login(string $username, string $password) : void{
		$this->password = $password;

		$this->client->get("https://account.riotgames.com");

		$response = $this->client->put("https://auth.riotgames.com/api/v1/authorization", [
			RequestOptions::JSON => [
				"type" => "auth",
				"username" => $username,
				"password" => $password,
				"remember" => false,
			],
			RequestOptions::HEADERS => [
				"Accept: application/json",
				"Accepted-Laungeage: ja,en-US;q=0.7,en;q=0.3",
				"Context-Type: application/json",
				"Origin: https://authenticate.riotgames.com",
				"Referer: https://authenticate.riotgames.com"
			]
		]);

		$response = json_decode($response->getBody()->getContents(), true);
		$response = match ($response["type"]) {
			"response" => $response["response"],
			"auth" => throw new AuthenticationException($response["error"], ExceptionErrorCode::AUTH_ERROR),
			"multifactor" => throw new AuthenticationException("You need to get past the 2FA.", ExceptionErrorCode::NEED_2FA)
		};

		var_dump($response->getBody()->getContents());

		$this->client->get($response["parameters"]["uri"]);

		$this->loggedIn = true;
	}

	public function auth2FA(string $code) : void{
		$response = json_decode($this->client->put("https://auth.riotgames.com/api/v1/authorization", [
			RequestOptions::JSON => [
				"type" => "multifactor",
				"code" => $code,
				"rememberDevice" => false
			],
			RequestOptions::HEADERS => [
				"Accept: application/json",
				"Accepted-Laungeage: ja,en-US;q=0.7,en;q=0.3",
				"Context-Type: application/json",
				"Origin: https://authenticate.riotgames.com",
				"Referer: https://authenticate.riotgames.com"
			]
		])->getBody()->getContents(), true);

		$response = match ($response["type"]) {
			"response" => $response["response"],
			"auth" => throw new AuthenticationException($response["error"]),
		};

		$this->client->get($response["parameters"]["uri"]);

		$this->loggedIn = true;
	}

	public function changePassword(string $newPassword) : void{
		if(!$this->loggedIn) throw new AuthenticationException("You are not logged in.", ExceptionErrorCode::NOT_LOGGED_IN);

		$response = $this->client->get("https://account.riotgames.com");
		$csrfToken = explode("\"", explode("csrf-token\" content=", $response->getBody()->getContents())[1])[1];

		$response = $this->client->put("https://account.riotgames.com/api/account/v1/user/password", [
			RequestOptions::JSON => [
				"currentPassword" => $this->password,
				"password" => $newPassword
			],
			RequestOptions::HEADERS => [
				"csrf-token" => $csrfToken,
				"Referer" => "https://account.riotgames.com"
			]
		]);

		$data = json_decode($response->getBody()->getContents(), true);

		if($response->getStatusCode() === 422 && $data["errorCode"] === "validation_error"){
			if(isset($data["errors"]["password"])){
				match($data["errors"]["password"]){
					"invalid_password_format" => throw new ValidationException("Invalid password format.", ExceptionErrorCode::INVALID_PASSWORD_FORMAT),
					"weak_password" => throw new ValidationException("This new password is weak.", ExceptionErrorCode::WEAK_PASSWORD)
				};
			}elseif(isset($data["errors"]["currentPassword"])){
				match ($data["errors"]["currentPassword"]) {
					"incorrect_password" => throw new ValidationException("Current password is incorrect.", ExceptionErrorCode::INCORRECT_PASSWORD)
				};
			}
		}elseif($response->getStatusCode() === 403){
			$this->loggedIn = false;
			throw new AuthenticationException("You are not logged in.", ExceptionErrorCode::NOT_LOGGED_IN);
		}
	}
}