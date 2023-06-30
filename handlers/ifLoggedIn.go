package handlers

import (
	"database/sql"
	"fmt"
	"forum/structs"
	"net/http"
)

type userInfo struct {
	User structs.User
}

func IsLoggedIn(r *http.Request, db *sql.DB) userInfo {
	fmt.Println("[IfLoggedIn]")
	info := userInfo{}

	cookie, err := r.Cookie("forum-session")
	for _, c := range r.Cookies() {
		fmt.Println(c)
	}
	if err != nil {
		fmt.Println("[IfLoggedIn] cookie err", err.Error())
		info.User.LoggedIn = false
		// Session ID cookie not found
		return info
	}
	sessionID := cookie.Value
	fmt.Println("[IfLoggedIn] session id:", sessionID)
	if sessionID == "" {
		info.User.LoggedIn = false
		return info
	}

	// Check if the session ID exists in the database
	row := db.QueryRow("SELECT username FROM authenticated_users WHERE session_id = ?;", sessionID)
	var username string
	err = row.Scan(&username)
	if err == sql.ErrNoRows {
		// Session ID does not exist in the database
		info.User.LoggedIn = false
		return info
	} else if err != nil {
		// Error occurred while querying the database
		info.User.LoggedIn = false
		return info
	}

	fmt.Println("[IfLoggedIn] id in database")

	// Check if the session ID exists in the database
	row = db.QueryRow("SELECT uuid FROM users WHERE username = ?;", username)
	var uuid string
	err = row.Scan(&uuid)
	if err == sql.ErrNoRows {
		return info
	} else if err != nil {
		return info
	}

	fmt.Println("[IfLoggedIn] uuid in database")

	info.User.ID = uuid
	info.User.Username = username
	info.User.LoggedIn = true

	fmt.Println("[IfLoggedIn] ifloggedin user info:", info.User)
	fmt.Println("[IfLoggedIn] info:", info)
	return info
}
