package models

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

type SuccessResponse struct {
	Message string `json:"message,omitempty"`
	Data    any    `json:"data"`
}

type CreateUserSuccess struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
}

type LoginSuccess struct {
	Token    string `json:"token"`
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
}

type DeleteUserSuccess struct {
	UserID uint `json:"user_id"`
}

type UpdateUserSuccess = CreateUserSuccess

type ResponsePassword struct {
	Name          string `json:"name"`
	Value         string `json:"value"`
	IV            string `json:"iv"`
	AuthTag       string `json:"auth_tag"`
	Salt          string `json:"salt"`
	AssociatedURL string `json:"associated_url,omitempty"`
}

type GetPasswordsSuccess struct {
	Passwords []ResponsePassword `json:"passwords"`
}

type AddPasswordSuccess struct {
	NewPassword ResponsePassword `json:"new_password"`
}

type DeletePasswordSuccess struct {
	Name string `json:"name"`
}

type UpdatePasswordSuccess = AddPasswordSuccess
