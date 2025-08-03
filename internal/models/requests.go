package models

import "net/http"

// Password max len of 72 because of bcrypt limitations
type CreateUserRequest struct {
	Username string `json:"username" validate:"required,min=4,max=32,username_format"`
	Password string `json:"password" validate:"required,min=12,max=72,password_strength"`
}

type LoginRequest struct {
	Username string `json:"username" validate:"required,min=4,max=32,username_format"`
	Password string `json:"password" validate:"required,min=12,max=72,password_strength"`
}

type UpdateUserRequest = CreateUserRequest

type AddPasswordRequest struct {
	Name          string `json:"name" validate:"required,min=1,max=100,password_name"`
	Value         string `json:"value" validate:"required,hexadecimal,len=512"`
	IV            string `json:"iv" validate:"required,hexadecimal,len=24"`
	AuthTag       string `json:"auth_tag" validate:"required,hexadecimal,len=32"`
	Salt          string `json:"salt" validate:"required,hexadecimal,len=32"`
	AssociatedURL string `json:"associated_url" validate:"omitempty,url,max=2048"`
}

type DeletePasswordRequest struct {
	Name string `json:"name" validate:"required,min=1,max=100,password_name"`
}

type UpdatePasswordRequest struct {
	AddPasswordRequest
	NewName string `json:"new_name" validate:"required,min=1,max=100,password_name"`
}

type RequestHandlerStruct struct {
	Handler func(http.ResponseWriter, *http.Request)
	Method  string
	Route   string
}
