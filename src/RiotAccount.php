<?php

declare(strict_types=1);

namespace charindo\RiotAccount;

use GuzzleHttp\Client;
use GuzzleHttp\RequestOptions;

final class RiotAccount{

	private Client $client;

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

	public function login(string $username, string $password) : bool{
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

		$contents = $response->getBody()->getContents();

		$result = json_decode($contents, true);
		if(isset($result["error"])){
			echo "ログイン失敗" . PHP_EOL;
			return false;
		}

		$this->client->get(json_decode($contents, true)["response"]["parameters"]["uri"]);

		$this->loggedIn = true;
		return true;
	}

	public function changePassword(string $currentPassword, string $newPassword) : array{
		$response = $this->client->get("https://account.riotgames.com");
		$csrfToken = explode("\"", explode("csrf-token\" content=", $response->getBody()->getContents())[1])[1];

		$response = $this->client->put("https://account.riotgames.com/api/account/v1/user/password", [
			RequestOptions::JSON => [
				"currentPassword" => $currentPassword,
				"password" => $newPassword
			],
			RequestOptions::HEADERS => [
				"csrf-token" => $csrfToken,
				"Referer" => "https://account.riotgames.com"
			]
		]);

		return json_decode($response->getBody()->getContents(), true);
	}
}