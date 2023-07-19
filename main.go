package main

import (
	"fmt"
	"log"
	"net/http"

	"authservice/src/handlers"

	"github.com/gorilla/mux"
)

func main() {
	mainRouter := mux.NewRouter()
	authRouter := mainRouter.PathPrefix("/auth").Subrouter()
	authRouter.HandleFunc("/signup", handlers.SignupHandler)
	authRouter.HandleFunc("/signin", handlers.SigninHandler)

	server := &http.Server{
		Addr:    "127.0.0.1:9090",
		Handler: mainRouter,
	}
	err := server.ListenAndServe()
	if err != nil {
		log.Panic("Error Booting server")
	}

	fmt.Println("Server running in port 9090")
}
