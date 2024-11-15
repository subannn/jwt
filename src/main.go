package main

import (
	"github.com/subannn/auth/api"
	"github.com/subannn/auth/config"
	"github.com/subannn/auth/db"
	"github.com/subannn/auth/handlers"
)

func main() {
	config.InitConfig()

	db := db.NewDB()
	handler := handlers.NewHandlers(db)
	server := api.NewAPIServer(":8080", handler.Mux)

	handler.Handle()

	server.RunServer()
}
