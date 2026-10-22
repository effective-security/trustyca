package admin

import (
	"fmt"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/privpb"
)

// CAOrgCmd is the base command of the org onboarding
type CAOrgCmd struct {
	Bootstrap OrgBootstrapCmd `cmd:"" help:"onboard an org: register its first issuing CA under a platform issuer and copy the template profiles"`
}

// OrgBootstrapCmd onboards an org (DESIGN.md section 6): it registers the
// first issuing CA of the org, signed by a platform issuer with a CA profile
// the platform issuer allows, then copies the template profiles of a
// directory into the org. A template bound to no issuer (an empty
// issuer_label) is bound to the new issuer; one bound to any issuer (*) is
// kept and listed in the allowed profiles of the new issuer, unless the
// command names them. The issuer is registered before the profiles, so a
// profile that fails leaves the issuer in place: register the profile with
// `ca profile register` and continue.
type OrgBootstrapCmd struct {
	OrgScope       `embed:""`
	Templates      string `required:"" type:"existingdir" help:"the directory of the template profiles: one YAML file per profile, named after its label"`
	Parent         string `required:"" help:"the platform issuer that signs the issuing CA: its label or ID"`
	Profile        string `default:"tenant_ca" help:"the CA profile of the platform issuer that signs the issuing CA"`
	Label          string `default:"issuing" help:"the label of the issuing CA"`
	SubjectFlags   `embed:""`
	KeyFlags       `embed:""`
	IssuerSettings `embed:""`
}

// Run the command
func (a *OrgBootstrapCmd) Run(app App) error {
	templates, err := LoadProfiles(a.Templates)
	if err != nil {
		return err
	}
	var wildcard []string
	for _, def := range templates {
		switch def.IssuerLabel {
		case "":
			def.IssuerLabel = a.Label
		case model.AnyIssuerLabel:
			wildcard = append(wildcard, def.Label)
		}
	}
	parentID, err := a.parentID(app)
	if err != nil {
		return err
	}
	subject := a.Subject()
	if subject == nil {
		subject = &pb.X509Subject{CommonName: a.Label}
	}
	settings := a.Config()
	if len(wildcard) > 0 && (settings == nil || len(settings.AllowedProfiles) == 0) {
		if settings == nil {
			settings = &pb.IssuerConfig{}
		}
		settings.AllowedProfiles = wildcard
	}

	client, err := app.CAClient()
	if err != nil {
		return err
	}
	ctx := app.Context()
	issuer, err := client.RegisterIssuer(ctx, &pb.RegisterIssuerRequest{
		OrgID:       a.Org,
		ProjectID:   a.Project,
		Label:       a.Label,
		Type:        pb.AuthorityType_Issuing,
		Subject:     subject,
		KeySpec:     a.Spec(),
		KeyProvider: a.KeyProvider,
		ParentID:    parentID,
		Profile:     a.Profile,
		Config:      settings,
	})
	if err != nil {
		return err
	}
	_ = app.Print(issuer)

	profiles := &pb.ProfilesResponse{}
	for _, def := range templates {
		res, err := client.RegisterProfile(ctx, &pb.RegisterProfileRequest{
			OrgID:     a.Org,
			ProjectID: a.Project,
			Profile:   def,
		})
		if err != nil {
			return errors.WithMessagef(err, "issuer %s is registered; unable to register profile %s", issuer.ID, def.Label)
		}
		profiles.Profiles = append(profiles.Profiles, res)
	}
	fmt.Fprintf(app.Writer(), "%d profiles registered\n", len(profiles.Profiles))
	return app.Print(profiles)
}

// parentID returns the ID of the platform issuer the command names: by ID,
// or by the label of an Active platform issuer, through the support list
func (a *OrgBootstrapCmd) parentID(app App) (string, error) {
	if isID(a.Parent) {
		return a.Parent, nil
	}
	client, err := app.AdminClient()
	if err != nil {
		return "", err
	}
	res, err := client.ListIssuers(app.Context(), &privpb.ListIssuersRequest{
		Platform: true,
		Label:    a.Parent,
		Status:   pb.IssuerStatus_Active,
		Limit:    2,
	})
	if err != nil {
		return "", err
	}
	switch len(res.Issuers) {
	case 0:
		return "", errors.Errorf("active platform issuer not found: %s", a.Parent)
	case 1:
		return res.Issuers[0].ID, nil
	default:
		// the label of a platform issuer is unique in the platform scope
		return "", errors.Errorf("platform issuer label is ambiguous: %s", a.Parent)
	}
}
