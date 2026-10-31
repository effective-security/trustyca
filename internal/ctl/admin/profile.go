package admin

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/effective-security/trustyca/privpb"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/ca/pbconv"
	"github.com/effective-security/x/configloader"
	"github.com/effective-security/x/fileutil/resolve"
	"github.com/effective-security/xpki/authority"
)

// ProfileCmd is the base command of the certificate profiles
type ProfileCmd struct {
	List     ProfileListCmd     `cmd:"" help:"list the profiles of an org"`
	Get      ProfileGetCmd      `cmd:"" help:"get a profile of an org by ID or label"`
	Register ProfileRegisterCmd `cmd:"" help:"create or replace a profile of an org from a YAML file"`
	Delete   ProfileDeleteCmd   `cmd:"" help:"delete a profile of an org"`
}

// ProfileListCmd lists the profiles of an org
type ProfileListCmd struct {
	OrgScope  `embed:""`
	Issuer    string `help:"the issuer label to filter by"`
	PageFlags `embed:""`
}

// Run the command
func (a *ProfileListCmd) Run(app App) error {
	client, err := app.BackendClient()
	if err != nil {
		return err
	}
	res, err := client.ListProfiles(app.Context(), &privpb.ListProfilesRequest{
		OrgID:       a.Org,
		ProjectID:   a.Project,
		IssuerLabel: a.Issuer,
		Limit:       a.Limit,
		Offset:      a.Offset,
		Cursor:      a.Cursor,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}

// ProfileGetCmd returns a profile of an org
type ProfileGetCmd struct {
	OrgScope `embed:""`
	ID       string `arg:"" optional:"" help:"the ID of the profile"`
	Label    string `help:"the label of the profile, resolved in the project then in the org"`
}

// Run the command
func (a *ProfileGetCmd) Run(app App) error {
	if a.ID == "" && a.Label == "" {
		return errors.New("profile ID or label is required")
	}
	client, err := app.BackendClient()
	if err != nil {
		return err
	}
	res, err := client.GetProfile(app.Context(), &privpb.GetProfileRequest{
		OrgID:     a.Org,
		ProjectID: a.Project,
		ID:        a.ID,
		Label:     a.Label,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}

// ProfileRegisterCmd creates or replaces a profile of an org, keyed by its
// label in the scope, from a file in the YAML shape of the profiles of a
// ca-config file
type ProfileRegisterCmd struct {
	OrgScope `embed:""`
	File     string `required:"" help:"the YAML file of the profile"`
	Label    string `help:"the label of the profile; the file name without its extension when empty"`
	Issuer   string `help:"the label of the issuer the profile binds to, or * for any issuer that allows it; replaces issuer_label of the file"`
}

// Run the command
func (a *ProfileRegisterCmd) Run(app App) error {
	def, err := LoadProfile(a.File, a.Label)
	if err != nil {
		return err
	}
	if a.Issuer != "" {
		def.IssuerLabel = a.Issuer
	}
	if def.IssuerLabel == "" {
		return errors.Errorf("profile %s: the issuer label is required: issuer_label of the file, or --issuer", def.Label)
	}
	client, err := app.BackendClient()
	if err != nil {
		return err
	}
	res, err := client.RegisterProfile(app.Context(), &privpb.RegisterProfileRequest{
		OrgID:     a.Org,
		ProjectID: a.Project,
		Profile:   def,
	})
	if err != nil {
		return err
	}
	return app.Print(res)
}

// ProfileDeleteCmd deletes a profile of an org
type ProfileDeleteCmd struct {
	Org     string `required:"" help:"the ID of the org"`
	Project string `help:"the ID of the project the profile belongs to; empty for any"`
	ID      string `arg:"" help:"the ID of the profile"`
}

// Run the command
func (a *ProfileDeleteCmd) Run(app App) error {
	client, err := app.BackendClient()
	if err != nil {
		return err
	}
	_, err = client.DeleteProfile(app.Context(), &privpb.DeleteProfileRequest{
		OrgID:     a.Org,
		ProjectID: a.Project,
		ID:        a.ID,
	})
	if err != nil {
		return err
	}
	return nil
}

// ProfileFileExtensions are the extensions of the profile files of a
// templates directory
var ProfileFileExtensions = []string{".yaml", ".yml"}

// LoadProfile reads a profile definition from a file in the YAML shape of
// the profiles of a ca-config file (authority.CertProfile), under the label,
// or the file name without its extension when the label is empty. The
// definition is validated as the service validates it, so a mistake is
// reported before anything is sent.
func LoadProfile(file, label string) (*pb.CertProfile, error) {
	file = resolve.ExpandPath(file)
	if label == "" {
		base := filepath.Base(file)
		label = strings.TrimSuffix(base, filepath.Ext(base))
	}
	var profile authority.CertProfile
	err := configloader.Unmarshal(file, &profile)
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to read profile %s", label)
	}
	def := pbconv.ProfileToPb(label, &profile)
	if _, err := pbconv.ProfileFromPb(def); err != nil {
		return nil, errors.WithMessagef(err, "profile %s", label)
	}
	return def, nil
}

// LoadProfiles reads the profile files of a directory, one profile per file
// named after its label, in file name order
func LoadProfiles(dir string) ([]*pb.CertProfile, error) {
	dir = resolve.ExpandPath(dir)
	var files []string
	for _, ext := range ProfileFileExtensions {
		matches, err := filepath.Glob(filepath.Join(dir, "*"+ext))
		if err != nil {
			return nil, errors.WithMessagef(err, "unable to list the profiles of %s", dir)
		}
		files = append(files, matches...)
	}
	if len(files) == 0 {
		return nil, errors.Errorf("no profile files in %s", dir)
	}
	slices.Sort(files)
	res := make([]*pb.CertProfile, 0, len(files))
	for _, file := range files {
		def, err := LoadProfile(file, "")
		if err != nil {
			return nil, err
		}
		res = append(res, def)
	}
	return res, nil
}
