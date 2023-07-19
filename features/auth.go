package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type AuthUser struct {
	email        string
	username     string
	passwordhash string
	fullname     string
	createDate   string
	role         int
}

// TODO: use a real database instead
var userList []AuthUser

func GetAuthUserObject(email string) (AuthUser, bool) {
	for _, user := range userList {
		if user.email == email {
			return user, true
		}
	}

	return AuthUser{}, false
}

func (u *AuthUser) ValidatePasswordHash(pswdhash string) bool {
	return u.passwordhash == pswdhash
}

func AddUserObject(email string, username string, passwordhash string, fullname string, role int) bool {
	newAuthUser := AuthUser{
		email:        email,
		passwordhash: passwordhash,
		username:     username,
		fullname:     fullname,
		role:         role,
	}

	for _, ele := range userList {
		if ele.email == email || ele.username == username {
			return false
		}
	}
	userList = append(userList, newAuthUser)
	return true
}

func GenerateToken(header string, payload map[string]string, secret string) (string, error) {
	h := hmac.New(sha256.New, []byte(secret))
	header64 := base64.StdEncoding.EncodeToString([]byte(header))

	payloadstr, err := json.Marshal(payload)
	if err != nil {
		fmt.Println("Error generating token")
		return string(payloadstr), err
	}

	payload64 := base64.StdEncoding.EncodeToString([]byte(payloadstr))

	message := header64 + "." + payload64

	unsignedStr := header + string(payloadstr)

	h.Write([]byte(unsignedStr))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))

	tokenStr := message + "." + signature
	return tokenStr, nil
}

func ValidateToken(token string, secret string) (bool, error) {
	splitToken := strings.Split(token, ".")
	if len(splitToken) != 3 {
		return false, nil
	}

	header, err := base64.StdEncoding.DecodeString(splitToken[0])
	if err != nil {
		return false, nil
	}

	payload, err := base64.StdEncoding.DecodeString(splitToken[1])
	if err != nil {
		return false, nil
	}

	unsignedStr := string(header) + string(payload)

	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(unsignedStr))

	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))
	fmt.Println(signature)

	if signature != splitToken[2] {
		return false, nil
	}

	return true, nil
}
