package safe

import (
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"time"
)

type Safe struct {
	CreatedOn int64                 `json:"createdOn"`
	CreatedBy string                `json:"createdBy"`
	Data      map[string]Credential `json:"data"`
}

type Credential struct {
	Alias     string `json:"alias"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	CreatedOn int64  `json:"createdOn"`
}

var masterPassword string

// New creates a new safe at the safePath.
func New(safePath string) (safe *Safe, err error) {
	usr, err := user.Current()
	if err != nil {
		return nil, err
	}

	safe = &Safe{
		time.Now().Unix(),
		usr.Name,
		make(map[string]Credential),
	}

	return safe, nil
}

// Save encrypts the safe with the provided password and writes
// it to disk.
func (safe *Safe) Save(safePath string) (err error) {
	encryptedSafe, err := EncryptText(safe.toJson(), getMasterPassword(
		"Enter a master password to lock your safe"))

	err = ioutil.WriteFile(safePath, []byte(encryptedSafe), 0600)
	if err != nil {
		return
	}

	return
}

// Load loads the encrypted Safe file at safePath, decrypts the file, and
// returns the Safe.
func Load(safePath string) (safe *Safe, err error) {
	if !Exists(safePath) {
		return nil, errors.New("Safe does not exist")
	}

	encryptedSafe, err := ioutil.ReadFile(safePath)
	if err != nil {
		return
	}

	decryptedSafe, err := DecryptText(string(encryptedSafe), getMasterPassword(
		"Enter a master password to unlock your safe"))
	if err != nil {
		log.Fatal(err)
	}

	err = json.Unmarshal([]byte(decryptedSafe), &safe)
	if err != nil {
		log.Fatal(err)
	}

	if safe.Data == nil {
		safe.Data = make(map[string]Credential)
	}

	return
}

// Exists is used to check if there is a safe at safePath.
func Exists(safePath string) bool {
	if _, err := os.Stat(safePath); os.IsNotExist(err) {
		return false
	}

	return true
}

// AddCredential creates a new credential with the provided details
func (safe *Safe) AddCredential(alias string, username string, password string) (err error) {
	if _, exists := safe.Data[alias]; exists {
		return fmt.Errorf("Credential with alias '%s' already exists", alias)
	}

	credential := Credential{alias, username, password, time.Now().Unix()}
	safe.Data[alias] = credential

	return
}

// GetCredential returns the credential with the provided alias.
func (safe *Safe) GetCredential(alias string) (cred Credential, err error) {
	if _, ok := safe.Data[alias]; !ok {
		err = fmt.Errorf("Credential with alias '%s' does not exist", alias)
		return Credential{}, err
	}

	return safe.Data[alias], nil
}

// RemoveCredential deletes the credential with the provided alias.
func (safe *Safe) RemoveCredential(alias string) (err error) {
	if _, ok := safe.Data[alias]; !ok {
		err = fmt.Errorf("Credential with alias '%s' does not exist", alias)
		return err
	}

	delete(safe.Data, alias)
	return nil
}

func getMasterPassword(prompt string) string {
	if masterPassword == "" {
		masterPassword = getPassword(prompt)
	}

	return masterPassword
}

// TODO(): This func is copied from pick.go
func getPassword(prompt string) string {
	fmt.Printf("%s\n> ", prompt)
	password, err := terminal.ReadPassword(0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\n")

	return string(password)
}

// toJson marshals the safe to JSON.
func (safe *Safe) toJson() string {
	j, _ := json.Marshal(safe)

	return string(j)
}
