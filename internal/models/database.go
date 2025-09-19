package models

import "gorm.io/gorm"

type StoredPassword struct {
	gorm.Model
	UserID        uint   `gorm:"not null"`
	Name          string `gorm:"not null"`
	Value         []byte `gorm:"type:BYTEA;not null"`
	IV            []byte `gorm:"type:BYTEA;not null"`
	AuthTag       []byte `gorm:"type:BYTEA;not null"`
	Salt          []byte `gorm:"type:BYTEA;not null"`
	AssociatedURL string
}

type User struct {
	gorm.Model      `validate:"-"`
	Username        string           `gorm:"uniqueIndex;not null"`
	PasswordHash    string           `gorm:"not null"`
	StoredPasswords []StoredPassword `gorm:"foreignKey:UserID"`
}
