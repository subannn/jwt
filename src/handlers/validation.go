package handlers

import (
	"net/http"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

func validatePassword(p string) bool {
	if len(p) < 6 || len(p) > 14 {
		return false
	}
	for _, r := range p {
		if !unicode.IsDigit(r) && !unicode.IsLetter(r) {
			return false
		}
	}

	st := make(map[rune]struct{})
	for _, ch := range p {
		st[ch] = struct{}{}
	}
	if len(st) < 6 {
		return false
	}

	return true
}

func validateRegistrationEmail(email string, h *Handler) bool {
	if len(email) < 6 || len(email) > 254 {
		return false
	}

	u, err := h.Storage.GetUserByEmail(email)
	if u != nil || err != nil {
		// log.Panic(err)
		return false
	}

	return true
}

func validateLogInEmail(email string, h *Handler) bool {
	if len(email) < 6 || len(email) > 254 {
		return false
	}
	u, err := h.Storage.GetUserByEmail(email)
	if u == nil || err != nil {
		return false
	}

	return true
}

func checkPasswordHash(hash, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func IsUserExist(userEmail string, w http.ResponseWriter, h *Handler) bool {
	userStorage, err := h.Storage.GetUserByEmail(userEmail)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false
	}
	if userStorage == nil {
		http.Error(w, "Such user does not exist.", http.StatusBadRequest)
		return false
	}
	return true
}
