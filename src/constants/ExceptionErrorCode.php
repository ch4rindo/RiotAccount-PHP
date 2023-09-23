<?php

namespace charindo\RiotAccount\constants;

class ExceptionErrorCode{

	public const NEED_2FA = 100;
	public const AUTH_ERROR = 101;
	public const NOT_LOGGED_IN = 102;

	public const INVALID_PASSWORD_FORMAT = 103;
	public const WEAK_PASSWORD = 104;
	public const INCORRECT_PASSWORD = 105;
}