package user

import (
	"fmt"
	"net/http"
	"time"
)

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("[LogoutHandler]")
	deleteCookie(w, "forum-session", r)
	http.Redirect(w, r, "/", http.StatusFound)
}

// Delete session cookie
func deleteCookie(w http.ResponseWriter, name string, r *http.Request) {
	fmt.Println("[deleteCookie]")
	cookie := &http.Cookie{
		Name:    name,
		Value:   "",
		Expires: time.Unix(0, 0), // Set the expiration time to a past time to delete the cookie
	}

	http.SetCookie(w, cookie)

	for _, c := range r.Cookies() {
		fmt.Println(c)
	}
}
