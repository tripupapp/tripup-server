package auth

import (
	"context"
	"io"
	"log"
	"os"

	"google.golang.org/api/option"

	firebase "firebase.google.com/go"
	firebaseAuth "firebase.google.com/go/auth"
)

var client *firebaseAuth.Client
var errLogger = log.New(os.Stderr, "[ERROR] ServerLog: ", log.LstdFlags | log.Lshortfile)

// InitialiseFirebaseAuthBackend initialises the firebase backend client
func InitialiseFirebaseAuthBackend(credentialsFilePath *string) {
	// initialise sdk
	var app *firebase.App
	var err error
	if credentialsFilePath == nil {
		app, err = firebase.NewApp(context.Background(), nil)
	} else {
		opt := option.WithCredentialsFile(*credentialsFilePath)
		app, err = firebase.NewApp(context.Background(), nil, opt)
	}
	if err != nil {
		errLogger.Fatalf("error initializing app: %v\n", err)
	}

	// get auth client
	client, err = app.Auth(context.Background())
	if err != nil {
		errLogger.Fatalf("error getting Auth client: %v\n", err)
	}
}

// GetUserAuthProviders provides the authorisation mechanisms contained by the users record on firebase
func GetUserAuthProviders(ctx context.Context, uid string) (AuthProviders, error) {
	var authProviders AuthProviders
	user, err := client.GetUser(ctx, uid)

	if err != nil {
		return authProviders, err
	}

	for _, userInfo := range user.ProviderUserInfo {
		if userInfo.ProviderID == "phone" {
			authProviders.PhoneNumber = shasum256(userInfo.PhoneNumber)
		}
		if userInfo.ProviderID == "password" {
			authProviders.Email = shasum256(userInfo.Email)
		}
		if userInfo.ProviderID == "apple.com" {
			authProviders.AppleID = shasum256(userInfo.Email)
		}
	}

	if authProviders == (AuthProviders{}) {
		return authProviders, io.EOF
	}

	return authProviders, nil
}
