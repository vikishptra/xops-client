package payload

type Response struct {
	Success bool `json:"success"`
	Message any  `json:"message"`
	Data    any  `json:"data"`
}

func NewSuccessResponse(data any, message any) Response {
	res := Response{
		Success: true,
		Message: message,
		Data:    data,
	}
	return res
}

func NewErrorResponse(messageError any) Response {
	res := Response{
		Success: false,
		Message: messageError,
	}
	return res
}
