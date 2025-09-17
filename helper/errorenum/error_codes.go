package errorenum

import (
	apperror "xops-admin/helper/appenerr"
)

const (
	MaxLengthExceeded                        = "The input value exceeds the allowed character limit"
	SomethingError        apperror.ErrorType = "Something error!"
	DataNotFound          apperror.ErrorType = "Data not Found"
	Unauthorized          apperror.ErrorType = "Unauthorized"
	OKSuccess             apperror.ErrorType = "OK"
	Forbidden             apperror.ErrorType = "Forbidden"
	InvalidRoutes         apperror.ErrorType = "Invalid routes!"
	DuplicateEmail        apperror.ErrorType = "Email already exists"
	FailedLogin           apperror.ErrorType = "Can't verify email or password. Please try again."
	SuccessLogin          apperror.ErrorType = "You're almost there, please enter your code to continue."
	AccountLocked         apperror.ErrorType = "Account temporarily locked due to multiple failed attempts."
	CodeVerifiedNull      apperror.ErrorType = "Please enter verification code."
	CodeVerifiedIsExpired apperror.ErrorType = "Code is expired. Please try a new one."
	CodeVerifiedSuccess   apperror.ErrorType = "A new OTP has been sent. Please check your email."
	CodeVerifiedFailed    apperror.ErrorType = "Can't verify the code you entered. Please check and retry."
	InvalidName           apperror.ErrorType = "Name is required"
	InvalidEmail          apperror.ErrorType = "Email is required"
	InvalidPassword       apperror.ErrorType = "Password is required"
	LogoCompanyRequired   apperror.ErrorType = "Logo company is required for client role"
	CompanyNameRequired   apperror.ErrorType = "Company name is required for client role"
	StartDateRequired     apperror.ErrorType = "Start date is required for client role"
	EndDateRequired       apperror.ErrorType = "End date is required for client role"
	InvalidDateRange      apperror.ErrorType = "start date must be before end date"
	DomainsRequired       apperror.ErrorType = "At least one domain is required for client role"
	InvalidDomainFormat   apperror.ErrorType = "Invalid domain format"
	RateLimit             apperror.ErrorType = "Account temporarily locked due to multiple failed attempts."
	FailedOtp             apperror.ErrorType = "Can't verify the code you entered. Please check and retry"
	ExpiredOtp            apperror.ErrorType = "Link expired. Please resend the code"
	CodeTidakValid        apperror.ErrorType = "Code tidak valid!"
	SendOtp               apperror.ErrorType = "A new OTP has been sent. Please check again."
	SuccessOtp            apperror.ErrorType = "Sign-in confirmed. You are now ready to use Dashboard"
)
