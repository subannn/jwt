package handlers

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/subannn/auth/config"
	jwtImpl "github.com/subannn/auth/jwt"
	"github.com/subannn/auth/models"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	Mux     *http.ServeMux
	Storage models.UsersStorage
}

func NewHandlers(storage models.UsersStorage) *Handler {
	mux := http.NewServeMux()
	return &Handler{
		Mux:     mux,
		Storage: storage,
	}
}

func (h *Handler) Handle() {
	h.Mux.HandleFunc("POST /register", h.registerHandler)
	h.Mux.HandleFunc("POST /login", h.loginHandler)
	h.Mux.HandleFunc("GET /validateToken", h.validateTokenHandler)
	h.Mux.HandleFunc("GET /ping", h.ping)
}

func (h *Handler) registerHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading body", http.StatusInternalServerError)
		return
	}
	if len(body) == 0 {
		http.Error(w, "Error reading body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	var user models.RegisterUser
	err = json.Unmarshal(body, &user)
	if err != nil {
		log.Println("Error during json decoding")
		http.Error(w, "Incorrect json struct", http.StatusBadRequest)
		return
	}

	if IsUserExist(user.Email, w, h) {
		http.Error(w, "Such user already exists", http.StatusBadRequest)
		return
	}

	if !validatePassword(user.Password) {
		http.Error(w, "Incorrect password format", http.StatusBadRequest)
		return
	}

	if !validateRegistrationEmail(user.Email, h) {
		http.Error(w, "Incorrect email format or email is already exist", http.StatusBadRequest)
		return
	}
	// TODO: Email validation
	cryptedHash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 5)

	if err != nil {
		log.Panic(err)
		return
	}
	user.Password = string(cryptedHash)
	h.Storage.SaveUser(user)
}

func (h *Handler) loginHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)

	if err != nil {
		http.Error(w, "Error reading body", http.StatusInternalServerError)
		return
	}
	if len(body) == 0 {
		http.Error(w, "Error reading body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	var user models.LogInUser
	err = json.Unmarshal(body, &user)
	if err != nil {
		log.Println("Error during json decoding")
		http.Error(w, "Incorrect json struct", http.StatusBadRequest)
		return
	}

	userStorage, err := h.Storage.GetUserByEmail(user.Email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if userStorage == nil {
		http.Error(w, "Such user does not exist.", http.StatusBadRequest)
		return
	}

	if checkPasswordHash(userStorage.Password, user.Password) {
		accessToken, refreshToken, err := jwtImpl.GenerateJWTs(*userStorage, config.JWTCfg.AccessTokenExp, config.JWTCfg.RefreshTokenExp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Authorization", "Bearer "+accessToken)

		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    refreshToken,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
		return
	}
	http.Error(w, "Incorrect Password", http.StatusBadRequest)
}

func (h *Handler) validateTokenHandler(w http.ResponseWriter, r *http.Request) {
	token, ok := r.Header["Authorization"]
	if !ok {
		http.Error(w, "Such user does not exist.", http.StatusBadRequest)
		return
	}
	str := strings.Split(token[0], " ")
	if len(str) < 2 {
		http.Error(w, "Invalid token", http.StatusBadRequest)
		return
	}
	claims, err := jwtImpl.ValidateToken(str[1])
	if err != nil {
		cookie, err := r.Cookie("refresh_token")
		if err != nil {
			http.Error(w, "Refresh token not found", http.StatusUnauthorized)
			return
		}
		refreshToken := cookie.Value
		_, err = jwtImpl.ValidateToken(refreshToken)
		if err != nil {
			http.Error(w, "Refresh token is incorrect", http.StatusUnauthorized)
			return
		}
	}
	user, err := jwtImpl.MapClaimsToUser(claims)
	if err != nil {
		log.Println(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	accessToken, err := jwtImpl.CreateAccessToken(*user, config.JWTCfg.AccessTokenExp)
	if err != nil {
		log.Println(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Authorization", "Bearer "+accessToken)
}

func (h *Handler) ping(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("PONG"))
}
