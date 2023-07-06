package api

import (
	"net/http"
)

func (app *Application) enableCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, X-CSRF-Token, Authorization")
			return
		} else {
			h.ServeHTTP(w, r)
		}
	})
}

func (app *Application) authRequired(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, clailms, err := app.JwtAuth.GetTokenFromHeaderAndVerify(w, r)

		if err != nil {
			app.errorJSON(w, err, http.StatusUnauthorized)
			return
		}

		if clailms["aud"] == nil {
			r.Header.Set("userID", clailms["sub"].(string))
		}

		h.ServeHTTP(w, r)
	})
}
