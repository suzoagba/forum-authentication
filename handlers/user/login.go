package user

import (
	"database/sql"
	"fmt"
	"forum/handlers"
	"forum/structs"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
)

func LoginHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		forPage := structs.ForPage{}
		forPage.User = handlers.IsLoggedIn(r, db).User
		forPage.Error.Error = false
		forPage.OAuth.GoogleID = GoogleClientID
		forPage.OAuth.GitHubID = GithubClientID
		if r.Method == http.MethodGet {
			if forPage.User.LoggedIn {
				http.Redirect(w, r, "/", http.StatusFound)
			} else {
				handlers.RenderTemplates("login", forPage, w, r)
			}
		} else if r.Method == http.MethodPost {
			emailLogin(w, r, db, forPage)
		}
	}
}

func emailLogin(w http.ResponseWriter, r *http.Request, db *sql.DB, forPage structs.ForPage) {
	err := r.ParseForm()
	if err != nil {
		forPage.Error.Error = true
		forPage.Error.Message = "Failed to parse form data"
		handlers.RenderTemplates("login", forPage, w, r)
		return
	}

	// Extract the user input values
	username := r.Form.Get("username")
	password := r.Form.Get("password")

	if passwordCorrect("SELECT password FROM users WHERE username = ?", username, password, db) {
		DoLogin(w, r, db, username, forPage)
		return

	} else {
		forPage.Error.Error = true
		forPage.Error.Message = "Check your username/password"
		handlers.RenderTemplates("login", forPage, w, r)
		return
	}
}

func passwordCorrect(query string, value string, password string, db *sql.DB) bool {
	row := db.QueryRow(query, value)

	var storedPassword string
	// Scan the retrieved password into the variable
	err := row.Scan(&storedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			// User not found in the database
			return false
		}
		return false
	}

	// Compare the stored password with the provided password
	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password))
	if err != nil {
		// Password does not match
		return false
	}

	return true
}

func DoLogin(w http.ResponseWriter, r *http.Request, db *sql.DB, username string, forPage structs.ForPage) {
	fmt.Println("[DoLogin]")
	sessionID := uuid.New().String()
	expiration := time.Now().Add(24 * time.Hour) // Set the expiration time for the cookie
	createCookie(w, "forum-session", sessionID, expiration, r)
	err := updateSessionID(username, sessionID, db)
	if err != nil {
		forPage.Error.Error = true
		forPage.Error.Message = "Unable to update session ID: " + err.Error() + "."
		handlers.RenderTemplates("login", forPage, w, r)
		return
	}
	err = addActiveSession(db, sessionID, username)
	if err != nil {
		forPage.Error.Error = true
		forPage.Error.Message = "Unable to add active session"
		handlers.RenderTemplates("login", forPage, w, r)
		return
	}
	fmt.Println("[DoLogin]", username, "logged in", sessionID, forPage.User)
	http.Redirect(w, r, "/", http.StatusFound)
	return
}

func updateSessionID(uuid, sessionID string, db *sql.DB) error {
	// Prepare the SQL statement
	fmt.Println("[updateSessionID]")
	fmt.Println("[updateSessionID] uuid, sessionid:", uuid, sessionID)
	stmt, err := db.Prepare("UPDATE authenticated_users SET session_id = ? WHERE username = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()

	// Execute the SQL statement
	_, err = stmt.Exec(sessionID, uuid)
	if err != nil {
		return err
	}

	return nil
}

// Create a new session cookie
func createCookie(w http.ResponseWriter, name, value string, expiration time.Time, r *http.Request) {
	fmt.Println("[createCookie]")
	cookie := &http.Cookie{
		Name:    name,
		Value:   value,
		Path:    "/",
		Expires: expiration,
	}
	fmt.Println("[createCookie]", cookie)

	http.SetCookie(w, cookie)

	for _, c := range r.Cookies() {
		fmt.Println(c)
	}
}

// Add new active session to the database
func addActiveSession(db *sql.DB, sessionID, username string) error {
	fmt.Println("[addActiveSession]")
	insertSQL := `
        INSERT OR REPLACE INTO authenticated_users (session_id, username)
        VALUES (?, ?);
    `

	_, err := db.Exec(insertSQL, sessionID, username)
	if err != nil {
		fmt.Println("[addActiveSession]", err.Error())
		return err
	}

	return nil
}
