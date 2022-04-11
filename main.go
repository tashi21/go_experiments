package main

import (
	"errors"
	"html/template"
	"log"
	"net/http"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Email    string
	Fname    string
	Lname    string
	Password []byte
}

var users = make(map[string]User)
var sessions = make(map[uuid.UUID]string)
var tpl *template.Template

func init() {
	tpl = template.Must(template.ParseGlob("go-templates/*.gohtml"))
}

// helper functions
func createUser(user User) error {
	// check if user with this email ID exists, only create a user if it doesn't exist
	if _, ok := users[user.Email]; !ok {
		users[user.Email] = user
		return nil
	}
	return errors.New("this email already exists. Use another email")
}

func createSession(w http.ResponseWriter, email string) error {
	// generate a UUID
	UUID, err := uuid.NewRandom()
	if err != nil {
		log.Fatalln(err)
	}
	// check if this session ID isn't already mapped to a user
	if _, ok := sessions[UUID]; !ok {
		// assign the user email to this sessions
		sessions[UUID] = email
		// set the cookie with the user details
		http.SetCookie(w, &http.Cookie{
			Name:  "session",
			Value: UUID.String(),
		})
		return nil
	}
	return errors.New("could not create session")
}

func checkUserStatus(r *http.Request) bool {
	// find the cookie names sessions
	c, err := r.Cookie("session")
	// if it doesn't exist, user is not logged in
	if err != nil {
		return false
	}
	UUID, err := uuid.Parse(c.Value)
	if err != nil {
		log.Fatalln(err)
	}
	// if session ID exists, check if a user is mapped to it
	_, ok := users[sessions[UUID]]
	return ok
}

// route handling functions
func index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	// data passed in is a bool giving user login status
	tpl.ExecuteTemplate(w, "index.gohtml", checkUserStatus(r))
}

func signup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	switch r.Method {
	case http.MethodGet:
		// redirect to homepage if user is already logged in
		if checkUserStatus(r) {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		w.WriteHeader(http.StatusOK)
		tpl.ExecuteTemplate(w, "signup.gohtml", nil)
	case http.MethodPost:
		email := r.PostFormValue("email")
		fname := r.PostFormValue("fname")
		lname := r.PostFormValue("lname")
		password, err := bcrypt.GenerateFromPassword([]byte(r.PostFormValue("password")), bcrypt.MinCost)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			tpl.ExecuteTemplate(w, "signup.gohtml", err.Error())
		}
		user := User{
			Email:    email,
			Fname:    fname,
			Lname:    lname,
			Password: password,
		}
		err = createUser(user)
		if err != nil {
			w.WriteHeader(http.StatusConflict)
			tpl.ExecuteTemplate(w, "signup.gohtml", err.Error())
			return
		}

		err = createSession(w, email)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			tpl.ExecuteTemplate(w, "signup.gohtml", err.Error())
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")

	switch r.Method {
	case http.MethodGet:
		// redirect to homepage if user is already logged in
		if checkUserStatus(r) {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		w.WriteHeader(http.StatusOK)
		tpl.ExecuteTemplate(w, "login.gohtml", nil)
	case http.MethodPost:
		email := r.PostFormValue("email")
		err := bcrypt.CompareHashAndPassword(users[email].Password, []byte(r.PostFormValue("password")))
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			tpl.ExecuteTemplate(w, "login.gohtml", err.Error())
			return
		}
		err = createSession(w, email)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			tpl.ExecuteTemplate(w, "login.gohtml", err.Error())
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func logout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	if checkUserStatus(r) {
		c, _ := r.Cookie("session")
		// delete session
		sID, _ := uuid.Parse(c.Value)
		delete(sessions, sID)
		c = &http.Cookie{
			Name:   "session",
			Value:  "",
			MaxAge: -1,
		}
		http.SetCookie(w, c)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func foo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	// only displays page if user is logged in, else redirect to home page
	if checkUserStatus(r) {
		c, err := r.Cookie("session")
		if err != nil {
			log.Fatalln(err)
		}
		http.SetCookie(w, c)
		UUID, err := uuid.Parse(c.Value)
		if err != nil {
			log.Fatalln(err)
		}
		user := users[sessions[UUID]]
		w.WriteHeader(http.StatusOK)
		tpl.ExecuteTemplate(w, "foo.gohtml", user)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func main() {
	http.HandleFunc("/", index)
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/foo", foo)
	http.ListenAndServe(":8080", nil)
}
