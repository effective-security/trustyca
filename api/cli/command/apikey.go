package command

import (
	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
)

// APIKeyCmd is the base command for API keys of the selected org
type APIKeyCmd struct {
	Create APIKeyCreateCmd `cmd:"" help:"create an API key; the secret is shown once"`
	List   APIKeyListCmd   `cmd:"" help:"list API keys"`
	Delete APIKeyDeleteCmd `cmd:"" help:"delete an API key"`
}

// APIKeyCreateCmd creates an API key
type APIKeyCreateCmd struct {
	Label     string   `kong:"arg" help:"the label of the key"`
	Scopes    []string `help:"the scopes granted to the key, e.g. certs:issue; defaults to read scopes"`
	Project   string   `help:"the ID of the project to restrict the key to"`
	ExpiresAt string   `help:"the expiration time in RFC3339 format; defaults to 90 days"`
}

// Run the command
func (a *APIKeyCreateCmd) Run(app App) error {
	client, err := app.OrgsClient()
	if err != nil {
		return err
	}
	res, err := client.CreateAPIKey(app.Context(), &pb.CreateAPIKeyRequest{
		Label:     a.Label,
		Scopes:    a.Scopes,
		ProjectID: a.Project,
		ExpiresAt: a.ExpiresAt,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}

// APIKeyListCmd lists API keys
type APIKeyListCmd struct {
	Project string `help:"the ID of the project to list the keys of"`
	Status  string `help:"the status to filter by"`
}

// Run the command
func (a *APIKeyListCmd) Run(app App) error {
	client, err := app.OrgsClient()
	if err != nil {
		return err
	}
	req := &pb.ListAPIKeysRequest{
		ProjectID: a.Project,
	}
	if a.Status != "" {
		req.Status = pb.ItemStatus_Unknown.Parse(a.Status)
		if req.Status == pb.ItemStatus_Unknown {
			return errors.Errorf("invalid status: %s", a.Status)
		}
	}
	res, err := client.ListAPIKeys(app.Context(), req)
	if err != nil {
		return err
	}
	return app.Print(res)
}

// APIKeyDeleteCmd deletes an API key
type APIKeyDeleteCmd struct {
	ID      string `kong:"arg" help:"the ID of the key"`
	Project string `help:"the ID of the project of the key"`
}

// Run the command
func (a *APIKeyDeleteCmd) Run(app App) error {
	client, err := app.OrgsClient()
	if err != nil {
		return err
	}
	res, err := client.DeleteAPIKey(app.Context(), &pb.APIKeyRequest{
		ID:        a.ID,
		ProjectID: a.Project,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}
