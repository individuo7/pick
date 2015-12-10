package main

import (
	"bufio"
	"cmd/safe"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/atotto/clipboard"
	"golang.org/x/crypto/ssh/terminal"
	"log"
	"os"
	"os/user"
	"strings"
)

const defaultPasswordLength = 50

var masterPassword string

// CopyCredential copies a credential's password to the clipboard.
func CopyCredential(alias string) {
	_safe, err := safe.Load(getSafePath())
	if err != nil {
		log.Fatal(err)
	}

	credential, err := _safe.GetCredential(alias)
	if err != nil {
		log.Fatal(err)
	}

	err = clipboard.WriteAll(credential.Password)
	if err != nil {
		log.Fatal(err)
	}
}

// DeleteCredential deletes a credential from the safe.
func DeleteCredential(alias string) {
	safePath := getSafePath()

	_safe, err := safe.Load(safePath)
	if err != nil {
		log.Fatal(err)
	}

	err = _safe.RemoveCredential(alias)
	if err != nil {
		log.Fatal(err)
	}

	err = _safe.Save(safePath)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Credential removed")
}

// ListCredentials displays all of the credentials in the safe.
func ListCredentials() {
	_safe, err := safe.Load(getSafePath())
	if err != nil {
		log.Fatal(err)
	}

	if credentials := _safe.Data; len(credentials) > 0 {
		for credential := range credentials {
			fmt.Println(credential)
		}
	} else {
		log.Fatal(errors.New("No credentials in safe"))
	}
}

// ReadCredential displays a single credential from the safe.
func ReadCredential(alias string) {
	_safe, err := safe.Load(getSafePath())
	if err != nil {
		log.Fatal(err)
	}

	credential, err := _safe.GetCredential(alias)
	if err != nil {
		log.Fatal(err)
	}

	formattedCredential, err := json.MarshalIndent(credential, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf(string(formattedCredential))
}

// WriteCredential writes a new credential to the safe.
func WriteCredential(alias string, username string, password string) {
	safePath := getSafePath()

	// 1. Get a safe
	_safe, err := loadOrCreateSafe(safePath)
	if err != nil {
		log.Fatal(err)
	}

	// 2. Collect any info that was not provided
	if alias == "" {
		alias = getInput("Enter an alias")
	}

	if _, credentialExists := _safe.Data[alias]; credentialExists {
		log.Fatal(errors.New("Credential for " + alias + " already exists"))
	}

	if username == "" {
		username = getInput("Enter a username for " + alias)
	}

	if password == "" {
		if getAnswer("Generate password", "y") {
			password, err = safe.GeneratePassword(defaultPasswordLength)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			password = getPassword("Enter your password for " + alias)
		}
	}

	// 3. Add the new credential to the safe
	err = _safe.AddCredential(alias, username, password)
	if err != nil {
		log.Fatal(err)
	}

	// 4. Save the safe
	err = _safe.Save(safePath)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Credential saved")
}

// getPassword asks the user to enter a password with prompt.
func getPassword(prompt string) string {
	fmt.Printf("%s\n> ", prompt)
	password, err := terminal.ReadPassword(0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\n")

	return string(password)
}

// getInput gets input from the user with prompt.
func getInput(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s\n> ", prompt)
	text, err := reader.ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}

	return string(text[:len(text)-1])
}

// getAnswer asks the user a y/n question and returns a boolean.
func getAnswer(question string, defaultChoice string) bool {
	prompt := question + "? (y/n)"

	yes := getInput(prompt)
	if yes == "" {
		yes = defaultChoice
	}

	return strings.Contains(yes, "y") || strings.Contains(yes, "yes")
}

// getSafePath returns the path to the encrypted safe file.
func getSafePath() string {
	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}

	// ~/.pick.safe
	return usr.HomeDir + "/.pick.safe"
}

// loadOrCreateSafe will return an existing safe, or create a new one, at the safePath.
func loadOrCreateSafe(safePath string) (s *safe.Safe, err error) {
	if safe.Exists(safePath) {
		s, err = safe.Load(safePath)

	} else {
		if getAnswer("Unable to find an existing safe, create new", "y") {
			s, err = safe.New(safePath)
		} else {
			// They chose not to create a new safe
			err = errors.New("You must create or provide a safe")
			s = &safe.Safe{}
		}
	}

	return
}
