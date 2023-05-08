package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	credentials "github.com/oras-project/oras-credentials-go"

	notationauth "github.com/notaryproject/notation/internal/auth"
	"github.com/notaryproject/notation/internal/cmd"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const urlDocHowToAuthenticate = "https://notaryproject.dev/docs/how-to/registry-authentication/"

type loginOpts struct {
	cmd.LoggingFlagOpts
	SecureFlagOpts
	passwordStdin bool
	server        string
}

func loginCommand(opts *loginOpts) *cobra.Command {
	if opts == nil {
		opts = &loginOpts{}
	}
	command := &cobra.Command{
		Use:   "login [flags] <server>",
		Short: "Login to registry",
		Long: `Log in to an OCI registry

Example - Login with provided username and password:
	notation login -u <user> -p <password> registry.example.com

Example - Login using $NOTATION_USERNAME $NOTATION_PASSWORD variables:
	notation login registry.example.com`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("no hostname specified")
			}
			opts.server = args[0]
			return nil
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := readPassword(opts); err != nil {
				return err
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLogin(cmd.Context(), opts)
		},
	}
	opts.LoggingFlagOpts.ApplyFlags(command.Flags())
	opts.SecureFlagOpts.ApplyFlags(command.Flags())
	command.Flags().BoolVar(&opts.passwordStdin, "password-stdin", false, "take the password from stdin")
	return command
}

func runLogin(ctx context.Context, opts *loginOpts) error {
	// set log level
	ctx = opts.LoggingFlagOpts.SetLoggerLevel(ctx)

	// initialize
	serverAddress := opts.server

	// input username and password by prompt
	reader := bufio.NewReader(os.Stdin)
	var err error
	if opts.Username == "" {
		opts.Username, err = readUsernameFromPrompt(reader)
		if err != nil {
			return err
		}
	}
	if opts.Password == "" {
		opts.Password, err = readPasswordFromPrompt(reader)
		if err != nil {
			return err
		}
	}
	cred := opts.Credential()

	// ping to validate the credential
	registry, err := getRegistryClient(ctx, &opts.SecureFlagOpts, serverAddress)
	if err != nil {
		return fmt.Errorf("failed to get registry client: %v", err)
	}
	registryName := registry.Reference.Registry
	if err := registry.Ping(ctx); err != nil {
		return fmt.Errorf("failed to login to %s: failed to validate the credential: %v", registryName, err)
	}

	// store the validated credential
	credsStore, err := notationauth.NewCredentialsStore()
	if err != nil {
		return fmt.Errorf("failed to get credentials store: %v", err)
	}
	credKey := registryName
	if credKey == "docker.io" {
		credKey = "https://index.docker.io/v1/"
	}
	if err := credsStore.Put(ctx, credKey, cred); err != nil {
		if !errors.Is(err, credentials.ErrPlaintextPutDisabled) {
			return fmt.Errorf("failed to login to %s: %v", registryName, err)
		}

		// native credentials store is not available
		savedCred, err := credsStore.Get(ctx, credKey)
		if err == nil && savedCred == cred {
			// identical credential
			fmt.Fprintf(os.Stderr, `Warning: Configuring credential helper to securely store credentials is recommended. 
									Please refer to %s for more information.`, urlDocHowToAuthenticate)
		} else {
			return fmt.Errorf(`failed to login to %s: 
							   the credential could not be saved because a credentials store is required to securely store the password. 
							   If you are unable to set up a credentials store, you can configure environment variables. 
							   Please refer to %s for more information`,
				registryName, urlDocHowToAuthenticate)
		}
	}

	fmt.Println("Login Succeeded")
	return nil
}

func readPassword(opts *loginOpts) error {
	if opts.passwordStdin {
		password, err := readLine(os.Stdin)
		if err != nil {
			return err
		}
		opts.Password = password
	}
	return nil
}

func readLine(r io.Reader) (string, error) {
	passwordBytes, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	password := strings.TrimSuffix(string(passwordBytes), "\n")
	password = strings.TrimSuffix(password, "\r")
	return password, nil
}

func readUsernameFromPrompt(reader *bufio.Reader) (string, error) {
	fmt.Print("Username: ")
	username, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("error reading username: %w", err)
	}
	username = strings.TrimSpace(username)
	return username, nil
}

func readPasswordFromPrompt(reader *bufio.Reader) (string, error) {
	fmt.Print("Password: ")
	if term.IsTerminal(int(os.Stdin.Fd())) {
		bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return "", fmt.Errorf("error reading password: %w", err)
		}
		fmt.Println()
		return string(bytePassword), nil
	} else {
		password, err := readLine(reader)
		if err != nil {
			return "", fmt.Errorf("error reading password: %w", err)
		}
		fmt.Println()
		return password, nil
	}
}
