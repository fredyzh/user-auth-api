package api

import (
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/v5/middleware"
)

func (app *Application) routes() http.Handler {
	// create a router mux
	mux := chi.NewRouter()
	mux.Use(middleware.Recoverer)
	mux.Use(app.enableCORS)

	mux.Post("/signin", app.Signin)
	mux.Post("/login", app.Login)
	mux.Post("/jwtauth", app.JwtAuthentication)
	mux.Post("/registerJwt", app.RegisterJwt)
	mux.Get("/health", app.Health)

	mux.Route("/admin", func(adminMux chi.Router) {
		adminMux.Use(app.authRequired)
		adminMux.Get("/testJwt", app.TestJwt)
		adminMux.Get("/refreshJwtauth", app.RefreshJwtauth)

		adminMux.Post("/updateJwtRegister", app.UpdateJwtRegister)
	})

	return mux
}
