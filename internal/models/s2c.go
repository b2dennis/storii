package models

type ErrorS2C struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

type SuccessS2C struct {
	Message string `json:"message,omitempty"`
	Data    any    `json:"data"`
}

type CreateUserS2C struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
}

type LoginS2C struct {
	Token    string `json:"token"`
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
}

type DeleteUserS2C struct {
	UserID uint `json:"user_id"`
}

type UpdateUserS2C = CreateUserS2C

type S2CPassword struct {
	Name          string `json:"name"`
	Value         string `json:"value"`
	IV            string `json:"iv"`
	AuthTag       string `json:"auth_tag"`
	Salt          string `json:"salt"`
	AssociatedURL string `json:"associated_url,omitempty"`
}

type ListPasswordsS2C struct {
	Passwords []S2CPassword `json:"passwords"`
}

type SetPasswordS2C struct {
	NewPassword S2CPassword `json:"new_password"`
}

type DeletePasswordS2C struct {
	Name string `json:"name"`
}

type UpdatePasswordS2C = SetPasswordS2C
