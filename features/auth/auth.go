package auth

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
