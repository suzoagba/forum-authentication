package oauth

import (
	"encoding/json"
	"fmt"
	"forum/structs"
	"io"
	"os"
)

var (
	Google structs.GoogleWeb
)

func GetGoogleInfo() {
	f, err := os.Open("oauth/google.json")
	if err != nil {
		fmt.Println(err)
	}
	defer f.Close()
	byteValue, _ := io.ReadAll(f)
	var fromFile structs.GoogleAuth
	json.Unmarshal(byteValue, &fromFile)
	Google = fromFile.Web
}
