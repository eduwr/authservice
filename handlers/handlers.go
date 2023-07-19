package handlers

import (
	"authservice/features/auth"
	"authservice/features/jwt"
	"errors"
	"fmt"
	"net/http"
	"time"
)

func SignupHandler(rw http.ResponseWriter, r *http.Request) {
	if _, ok := r.Header["Email"]; !ok {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte("Email Missing"))
		return
	}
	if _, ok := r.Header["Username"]; !ok {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte("Username Missing"))
		return
	}
	if _, ok := r.Header["Passwordhash"]; !ok {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte("Passwordhash Missing"))
		return
	}
	if _, ok := r.Header["Fullname"]; !ok {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte("Fullname Missing"))
		return
	}

	check := auth.AddUserObject(r.Header["Email"][0], r.Header["Username"][0], r.Header["Passwordhash"][0],
		r.Header["Fullname"][0], 0)

	if !check {
		rw.WriteHeader(http.StatusConflict)
		rw.Write([]byte("Email or Username already exists"))
		return
	}
	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte("User Created"))
}

// we need this function to be private
func getSignedToken() (string, error) {
	// we make a JWT Token here with signing method of ES256 and claims.
	// claims are attributes.
	// aud - audience
	// iss - issuer
	// exp - expiration of the Token
	claimsMap := map[string]string{
		"aud": "frontend.knowsearch.ml",
		"iss": "knowsearch.ml",
		"exp": fmt.Sprint(time.Now().Add(time.Minute * 1).Unix()),
	}
	// here we provide the shared secret. It should be very complex.
	// Also, it should be passed as a System Environment variable

	secret := "Secure_Random_String"
	header := "HS256"
	tokenString, err := jwt.GenerateToken(header, claimsMap, secret)
	if err != nil {
		return tokenString, err
	}
	return tokenString, nil
}

// searches the user in the database.
func validateUser(email string, passwordHash string) (bool, error) {
	usr, exists := auth.GetAuthUserObject(email)
	if !exists {
		return false, errors.New("user does not exist")
	}
	passwordCheck := usr.ValidatePasswordHash(passwordHash)

	if !passwordCheck {
		return false, nil
	}
	return true, nil
}

func SigninHandler(rw http.ResponseWriter, r *http.Request) {
	// validate the request first.
	if _, ok := r.Header["Email"]; !ok {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte("Email Missing"))
		return
	}
	if _, ok := r.Header["Passwordhash"]; !ok {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte("Passwordhash Missing"))
		return
	}

	valid, err := validateUser(r.Header["Email"][0], r.Header["Passwordhash"][0])
	if err != nil {
		rw.WriteHeader(http.StatusUnauthorized)
		rw.Write([]byte("User Does not Exist"))
		return
	}

	if !valid {
		rw.WriteHeader(http.StatusUnauthorized)
		rw.Write([]byte("Incorrect Password"))
		return
	}
	tokenString, err := getSignedToken()
	if err != nil {
		fmt.Println(err)
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte("Internal Server Error"))
		return
	}

	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte(tokenString))
}
