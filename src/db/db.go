package db

import (
	"database/sql"
	"errors"
	"fmt"
	"log"

	cfg "github.com/subannn/auth/config"
	"github.com/subannn/auth/models"

	_ "github.com/lib/pq"
)

type Storage struct {
	Db *sql.DB
}

func NewDB() models.UsersStorage {
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.DBCfg.Host, cfg.DBCfg.Port, cfg.DBCfg.User, cfg.DBCfg.Password, cfg.DBCfg.Name, cfg.DBCfg.SSLmode)

	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		log.Fatal("DB Connection failed")
	}

	return &Storage{
		Db: db,
	}
}

func (s *Storage) GetUserByEmail(userEmail string) (*models.User, error) {
	rows, err := s.Db.Query("SELECT id, name, surname, email, password FROM Users WHERE email = $1", userEmail)
	if err != nil {
		log.Println("Error executing query:", err)
		return nil, err
	}

	var users []models.User
	for rows.Next() {
		var user models.User

		if err := rows.Scan(&user.Id, &user.Name, &user.Surname, &user.Email, &user.Password); err != nil {
			log.Println("Error scanning row:", err)
			return nil, err
		}
		users = append(users, user)
	}
	if len(users) == 1 {
		return &users[0], nil
	}
	if len(users) > 1 {
		return nil, errors.New("More than one use with such email")
	}
	return nil, nil
}

func (s *Storage) SaveUser(user models.RegisterUser) error {
	_, err := s.Db.Exec("INSERT INTO users (name, surname, email, password) VALUES ($1, $2, $3, $4)", user.Name, user.Surname, user.Email, user.Password)
	if err != nil {
		log.Panic(err)
		return err
	}
	return nil
}
