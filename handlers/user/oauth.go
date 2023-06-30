package user

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"forum/handlers"
	"forum/structs"
	"github.com/google/uuid"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

var (
	GoogleClientID     = ""
	GoogleClientSecret = ""
	GoogleRedirectURI  = "http://localhost:8080/oauth/google"
	GithubClientID     = ""
	GithubClientSecret = ""
	GithubRedirectURI  = "http://localhost:8080/oauth/github"
)

// OauthHandler handles the OAuth callback request
func OauthHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provider := strings.Split(r.URL.Path, "/")[2]
		switch provider {
		case "google":
			googleCallbackHandler(w, r, db)
		case "github":
			githubCallbackHandler(w, r, db)
		}
	}
}

// googleCallbackHandler handles the callback request from Google OAuth
func googleCallbackHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	// Retrieve the authorization code from the request
	code := r.FormValue("code")
	if code == "" {
		http.Error(w, "Authorization code not found", http.StatusBadRequest)
		return
	}

	// Exchange the authorization code for an access token
	tokenURL := "https://accounts.google.com/o/oauth2/token"
	tokenPayload := fmt.Sprintf("code=%s&client_id=%s&client_secret=%s&redirect_uri=%s&grant_type=authorization_code", code, GoogleClientID, GoogleClientSecret, GoogleRedirectURI)

	response, err := http.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(tokenPayload))
	if err != nil {
		log.Println("Failed to exchange token:", err)
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}
	defer response.Body.Close()

	// Decode the access token from the response
	var tokenResponse struct {
		AccessToken string `json:"access_token"`
	}
	err = json.NewDecoder(response.Body).Decode(&tokenResponse)
	if err != nil {
		log.Println("Failed to decode token response:", err)
		http.Error(w, "Failed to decode token response", http.StatusInternalServerError)
		return
	}

	// Retrieve user information using the access token
	userInfoURL := "https://www.googleapis.com/oauth2/v2/userinfo"
	req, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		log.Println("Failed to create user info request:", err)
		http.Error(w, "Failed to create user info request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Authorization", "Bearer "+tokenResponse.AccessToken)

	client := &http.Client{}
	userInfoResponse, err := client.Do(req)
	if err != nil {
		log.Println("Failed to retrieve user info:", err)
		http.Error(w, "Failed to retrieve user info", http.StatusInternalServerError)
		return
	}
	defer userInfoResponse.Body.Close()

	// Decode the user information from the response
	var userInfo struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	err = json.NewDecoder(userInfoResponse.Body).Decode(&userInfo)
	if err != nil {
		log.Println("Failed to decode user info:", err)
		http.Error(w, "Failed to decode user info", http.StatusInternalServerError)
		return
	}

	username := strings.Split(userInfo.Email, "@")[0]      // Extract the username from the email address
	oauthRegisterLogin(w, r, db, username, userInfo.Email) // Perform the registration or login process
}

// githubCallbackHandler handles the callback request from GitHub OAuth
func githubCallbackHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	code := r.FormValue("code")
	if code == "" {
		http.Error(w, "Authorization code not found", http.StatusBadRequest)
		return
	}

	tokenURL := "https://github.com/login/oauth/access_token"
	tokenPayload := fmt.Sprintf("code=%s&client_id=%s&client_secret=%s&redirect_uri=%s", code, GithubClientID, GithubClientSecret, GithubRedirectURI)

	response, err := http.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(tokenPayload))
	if err != nil {
		log.Println("Failed to exchange token:", err)
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}
	defer response.Body.Close()

	accessToken, err := parseAccessToken(response.Body)
	if err != nil {
		log.Println("Failed to parse access token:", err)
		http.Error(w, "Failed to parse access token", http.StatusInternalServerError)
		return
	}

	userInfoURL := "https://api.github.com/user"
	req, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		log.Println("Failed to create user info request:", err)
		http.Error(w, "Failed to create user info request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{}
	userInfoResponse, err := client.Do(req)
	if err != nil {
		log.Println("Failed to retrieve user info:", err)
		http.Error(w, "Failed to retrieve user info", http.StatusInternalServerError)
		return
	}
	defer userInfoResponse.Body.Close()

	var userInfo struct {
		Username string `json:"login"`
		Email    string `json:"email"`
	}
	err = json.NewDecoder(userInfoResponse.Body).Decode(&userInfo)
	if err != nil {
		log.Println("Failed to decode user info:", err)
		http.Error(w, "Failed to decode user info", http.StatusInternalServerError)
		return
	}

	if userInfo.Email == "" {
		emailsURL := "https://api.github.com/user/emails"
		req, err := http.NewRequest("GET", emailsURL, nil)
		if err != nil {
			log.Println("Failed to create email request:", err)
			http.Error(w, "Failed to create email request", http.StatusInternalServerError)
			return
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Accept", "application/vnd.github.v3+json")

		emailsResponse, err := client.Do(req)
		if err != nil {
			log.Println("Failed to retrieve user emails:", err)
			http.Error(w, "Failed to retrieve user emails", http.StatusInternalServerError)
			return
		}
		defer emailsResponse.Body.Close()

		var emails []struct {
			Email      string `json:"email"`
			Primary    bool   `json:"primary"`
			Verified   bool   `json:"verified"`
			Visibility string `json:"visibility"`
		}
		err = json.NewDecoder(emailsResponse.Body).Decode(&emails)
		if err != nil {
			log.Println("Failed to decode user emails:", err)
			http.Error(w, "Failed to decode user emails", http.StatusInternalServerError)
			return
		}

		for _, email := range emails {
			if email.Primary && email.Verified && email.Visibility == "public" {
				userInfo.Email = email.Email
				break
			}
		}
	}

	oauthRegisterLogin(w, r, db, userInfo.Username, userInfo.Email)
}

// oauthRegisterLogin performs the registration or login process based on the provided username and email
func oauthRegisterLogin(w http.ResponseWriter, r *http.Request, db *sql.DB, username string, email string) {
	var usernameTaken bool
	if RowExists("SELECT email from users WHERE email = ?", email, db) { // if the email exists
		fmt.Println("[googleCallbackHandler] email already in db")
		username, _ = GetUsernameByEmail(db, email)

		forPage := structs.ForPage{}
		forPage.Error.Error = false
		forPage.User = handlers.IsLoggedIn(r, db).User
		fmt.Println("[googleCallbackHandler] starting DoLogin")
		DoLogin(w, r, db, username, forPage)
	} else {
		if RowExists("SELECT username from users WHERE username = ?", username, db) { // if username already taken
			fmt.Println("[googleCallbackHandler] username already in db")
			usernameTaken = true

			for usernameTaken {
				fmt.Println("[googleCallbackHandler] usernameTaken")
				if lastCharIsDigit(username) {
					// Get the last character as a digit
					lastDigit := getLastDigit(username)

					// Increment the digit by 1
					nextDigit := lastDigit + 1

					// Update the username by replacing the last digit with the incremented value
					username = username[:len(username)-1] + fmt.Sprintf("%d", nextDigit)
				} else {
					// Append "1" to the username
					username += "1"
				}

				// Check if the new username is taken in the database
				if !RowExists("SELECT username FROM users WHERE username = ?", username, db) {
					usernameTaken = false
				}
			}
		}
		fmt.Println("[googleCallbackHandler] starting DoRegister")
		DoRegister(w, r, db, false, email, username, uuid.New().String(), false)
	}
}

// parseAccessToken parses the access token from the response body
func parseAccessToken(responseBody io.Reader) (string, error) {
	bodyBytes, err := ioutil.ReadAll(responseBody)
	if err != nil {
		return "", err
	}

	responseParams := strings.Split(string(bodyBytes), "&")
	for _, param := range responseParams {
		keyValue := strings.Split(param, "=")
		if len(keyValue) == 2 && keyValue[0] == "access_token" {
			return keyValue[1], nil
		}
	}

	return "", fmt.Errorf("access_token not found in response")
}

// GetUsernameByEmail retrieves the username associated with the given email from the database
func GetUsernameByEmail(db *sql.DB, email string) (string, error) {
	fmt.Println("[GetUsernameByEmail]")
	var username string
	query := "SELECT username FROM users WHERE email = ?"

	row := db.QueryRow(query, email)
	err := row.Scan(&username)
	if err != nil {
		if err == sql.ErrNoRows {
			// Handle case when no matching row is found
			return "", fmt.Errorf("no user found with email: %s", email)
		}
		// Handle other query execution errors
		return "", fmt.Errorf("failed to retrieve username: %w", err)
	}

	return username, nil
}

// lastCharIsDigit checks if the last character of the given string is a digit
func lastCharIsDigit(s string) bool {
	if len(s) > 0 {
		lastChar := s[len(s)-1]
		return lastChar >= '0' && lastChar <= '9'
	}
	return false
}

// getLastDigit retrieves the last digit from the given string
func getLastDigit(s string) int {
	if len(s) > 0 {
		lastChar := s[len(s)-1]
		if lastChar >= '0' && lastChar <= '9' {
			return int(lastChar - '0')
		}
	}
	return 0
}
