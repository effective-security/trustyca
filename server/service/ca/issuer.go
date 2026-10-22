package ca

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/pb"
	core "github.com/effective-security/trustyca/internal/ca"
	"github.com/effective-security/trustyca/internal/ca/pbconv"
	"github.com/effective-security/trustyca/internal/db"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/db/pgsql/query"
	"github.com/effective-security/trustyca/internal/events"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/authority"
	"github.com/effective-security/xpki/certutil"
	"google.golang.org/grpc/codes"
)

// authorityProfile is the profile the authority signs with
type authorityProfile = authority.CertProfile

// issuerTransitions lists the lifecycle status an issuer may move to from
// its current one: Active -> Archived -> Destroyed
var issuerTransitions = map[pb.IssuerStatus_Enum]pb.IssuerStatus_Enum{
	pb.IssuerStatus_Active:   pb.IssuerStatus_Archived,
	pb.IssuerStatus_Archived: pb.IssuerStatus_Destroyed,
}

// RegisterIssuer creates an issuer of the org (DESIGN.md section 5.2): a
// self-signed root when the type is Root, an issuer signed by the parent
// when ParentID is set, otherwise a Pending issuer with its CSR. The key is
// generated in the crypto provider and never leaves it; a software key is
// stored wrapped.
func (s *Service) RegisterIssuer(ctx context.Context, req *pb.RegisterIssuerRequest) (*pb.Issuer, error) {
	if req == nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing request")
	}
	err := s.requireCA(ctx)
	if err != nil {
		return nil, err
	}
	label := strings.TrimSpace(req.Label)
	if label == "" {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing label")
	}
	if len(label) > model.MaxLenForLabel {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid label length")
	}
	if req.Type == pb.AuthorityType_Unknown {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing type")
	}
	if req.Type == pb.AuthorityType_Root && req.ParentID != "" {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "a Root issuer is self-signed: parent ID is not allowed")
	}
	if req.Subject == nil || (req.Subject.CommonName == "" && len(req.Subject.Names) == 0) {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing subject")
	}
	if _, _, err := core.KeySpec(req.KeySpec); err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "%s", err.Error())
	}
	if _, err := pbconv.IssuerConfigFromPb(label, req.Config); err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid config: %s", err.Error())
	}
	extensions, err := pbconv.ExtensionsFromPb(req.Extensions)
	if err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "%s", err.Error())
	}

	orgID, err := s.tenantOrg(ctx, req.OrgID)
	if err != nil {
		return nil, err
	}
	projectID, err := s.tenantProject(ctx, orgID, req.ProjectID)
	if err != nil {
		return nil, err
	}
	keys := s.registry.Keys()
	prov, err := keys.Provider(req.KeyProvider)
	if err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid key provider: %s", req.KeyProvider)
	}

	ireq := &core.IssuerRequest{
		OrgID:      orgID,
		ProjectID:  projectID,
		Label:      label,
		Type:       req.Type,
		Subject:    subjectOf(req.Subject),
		SAN:        req.SAN,
		Extensions: extensions,
		KeySpec:    req.KeySpec,
		Provider:   prov,
		Config:     req.Config,
	}
	var row *model.Issuer
	switch {
	case req.ParentID != "":
		if req.Profile == "" {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing profile")
		}
		parent, err := s.parentIssuer(ctx, orgID, projectID, req.ParentID, req.Profile)
		if err != nil {
			return nil, err
		}
		row, err = keys.NewSignedIssuer(ctx, ireq, parent)
		if err != nil {
			return nil, s.issuerError(ctx, err)
		}
	case req.Type == pb.AuthorityType_Root:
		if req.Profile == "" {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing profile")
		}
		profile, err := s.caProfile(ctx, orgID, projectID, req.Profile)
		if err != nil {
			return nil, err
		}
		row, err = keys.NewRootIssuer(ctx, ireq, req.Profile, profile)
		if err != nil {
			return nil, s.issuerError(ctx, err)
		}
	default:
		row, err = keys.NewPendingIssuer(ctx, ireq)
		if err != nil {
			return nil, s.issuerError(ctx, err)
		}
	}

	registered, err := s.registerIssuer(ctx, row)
	if err != nil {
		return nil, err
	}
	logger.ContextKV(ctx, xlog.NOTICE,
		"status", "issuer_registered",
		"issuer_id", registered.ID.UnderscoreString(),
		"org_id", registered.OrgID.UnderscoreString(),
		"project_id", registered.ProjectID.UnderscoreString(),
		"issuer", registered.Label,
		"type", registered.Type.String(),
		"issuer_status", registered.Status.String(),
		"skid", registered.Skid,
		"key_provider", registered.KeyProvider)
	events.New(ctx, ServiceName, pb.EventType_IssuerRegistered, "Issuer registered").
		Org(orgID).
		Project(projectID).
		Reference(registered.ID).
		Description("issuer %q registered with status %s", registered.Label, registered.Status.String()).
		Emit(s.orgs)
	return issuerPb(ctx, registered)
}

// ImportIssuer registers an issuer from an existing certificate and key:
// a key in a crypto provider by its URI, or a PEM key that is stored
// wrapped. The chain must verify to the given or the self-signed root.
func (s *Service) ImportIssuer(ctx context.Context, req *pb.ImportIssuerRequest) (*pb.Issuer, error) {
	if req == nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing request")
	}
	err := s.requireCA(ctx)
	if err != nil {
		return nil, err
	}
	label := strings.TrimSpace(req.Label)
	if label == "" {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing label")
	}
	if len(label) > model.MaxLenForLabel {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid label length")
	}
	if req.Type == pb.AuthorityType_Unknown {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing type")
	}
	if req.Certificate == "" {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing certificate")
	}
	if (req.KeyURI == "") == (req.KeyPem == "") {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "either key URI or key PEM is required")
	}
	orgID, err := s.tenantOrg(ctx, req.OrgID)
	if err != nil {
		return nil, err
	}
	projectID, err := s.tenantProject(ctx, orgID, req.ProjectID)
	if err != nil {
		return nil, err
	}

	row, err := s.registry.Keys().ImportIssuer(ctx, &core.ImportRequest{
		OrgID:         orgID,
		ProjectID:     projectID,
		Label:         label,
		Type:          req.Type,
		Certificate:   req.Certificate,
		Intermediates: req.Intermediates,
		Root:          req.Root,
		KeyURI:        req.KeyURI,
		KeyPEM:        req.KeyPem,
		Config:        req.Config,
	})
	if err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "failed to import issuer: %s", err.Error())
	}
	registered, err := s.registerIssuer(ctx, row)
	if err != nil {
		return nil, err
	}
	logger.ContextKV(ctx, xlog.NOTICE,
		"status", "issuer_imported",
		"issuer_id", registered.ID.UnderscoreString(),
		"org_id", registered.OrgID.UnderscoreString(),
		"project_id", registered.ProjectID.UnderscoreString(),
		"issuer", registered.Label,
		"type", registered.Type.String(),
		"skid", registered.Skid,
		"key_provider", registered.KeyProvider)
	events.New(ctx, ServiceName, pb.EventType_IssuerRegistered, "Issuer imported").
		Org(orgID).
		Project(projectID).
		Reference(registered.ID).
		Description("issuer %q imported", registered.Label).
		Emit(s.orgs)
	return issuerPb(ctx, registered)
}

// ActivateIssuer sets the externally signed certificate of a Pending
// issuer of the org and activates it; the certificate must be for the key
// of the issuer and its chain must verify
func (s *Service) ActivateIssuer(ctx context.Context, req *pb.ActivateIssuerRequest) (*pb.Issuer, error) {
	if req == nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing request")
	}
	err := s.requireCA(ctx)
	if err != nil {
		return nil, err
	}
	if req.Certificate == "" {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing certificate")
	}
	orgID, err := s.tenantOrg(ctx, req.OrgID)
	if err != nil {
		return nil, err
	}
	row, err := s.orgIssuer(ctx, orgID, req.ID, pb.CA_ActivateIssuer_FullMethodName)
	if err != nil {
		return nil, err
	}
	if row.Status != pb.IssuerStatus_Pending {
		return nil, preconditionFailed(ctx, "issuer is not pending")
	}
	activated, err := s.registry.Keys().ActivatedIssuer(ctx, row, req.Certificate, req.Intermediates, req.Root)
	if err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "failed to activate issuer: %s", err.Error())
	}
	res, err := s.db.ActivateIssuer(ctx, activated)
	if err != nil {
		switch {
		case xdb.IsNotFoundError(err):
			return nil, preconditionFailed(ctx, "issuer is not pending")
		case db.IsUniqueViolation(err, db.UniqueIssuerSkid):
			return nil, httperror.NewGrpcFromCtx(ctx, codes.AlreadyExists, "issuer key is already registered")
		}
		return nil, httperror.WrapWithCtx(ctx, err, "failed to activate issuer")
	}
	s.registry.InvalidateIssuer(res)
	logger.ContextKV(ctx, xlog.NOTICE,
		"status", "issuer_activated",
		"issuer_id", res.ID.UnderscoreString(),
		"org_id", res.OrgID.UnderscoreString(),
		"issuer", res.Label,
		"skid", res.Skid)
	events.New(ctx, ServiceName, pb.EventType_IssuerActivated, "Issuer activated").
		Org(orgID).
		Project(res.ProjectID).
		Reference(res.ID).
		Description("issuer %q activated", res.Label).
		Emit(s.orgs)
	return issuerPb(ctx, res)
}

// UpdateIssuer replaces the runtime settings of an issuer of the org, or
// moves it along its lifecycle: Active to Archived, Archived to Destroyed.
// Destroying an issuer removes its key from the crypto provider when the
// provider manages keys, and clears a wrapped software key.
func (s *Service) UpdateIssuer(ctx context.Context, req *pb.UpdateIssuerRequest) (*pb.Issuer, error) {
	if req == nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing request")
	}
	err := s.requireCA(ctx)
	if err != nil {
		return nil, err
	}
	if req.Config == nil && req.Status == pb.IssuerStatus_Unknown {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "nothing to update")
	}
	orgID, err := s.tenantOrg(ctx, req.OrgID)
	if err != nil {
		return nil, err
	}
	row, err := s.orgIssuer(ctx, orgID, req.ID, pb.CA_UpdateIssuer_FullMethodName)
	if err != nil {
		return nil, err
	}
	update := &query.UpdateIssuerRequest{
		ID:    row.ID.UInt64(),
		OrgID: orgID.UInt64(),
	}
	if req.Status != pb.IssuerStatus_Unknown {
		if issuerTransitions[row.Status] != req.Status {
			return nil, preconditionFailed(ctx, "issuer status %s cannot change to %s", row.Status.String(), req.Status.String())
		}
		update.Status = req.Status
	}
	if req.Config != nil {
		_, err := pbconv.IssuerConfigFromPb(row.Label, req.Config)
		if err != nil {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "invalid config: %s", err.Error())
		}
		j, err := model.MarshalJSONValue(req.Config)
		if err != nil {
			return nil, httperror.WrapWithCtx(ctx, err, "invalid config")
		}
		update.Config = json.RawMessage(j)
	}

	updated, err := s.db.UpdateIssuer(ctx, update)
	if err != nil {
		if xdb.IsNotFoundError(err) {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "issuer not found")
		}
		return nil, httperror.WrapWithCtx(ctx, err, "failed to update issuer")
	}
	if update.Status == pb.IssuerStatus_Destroyed {
		err := s.registry.Keys().Destroy(ctx, row)
		if err != nil {
			// the row no longer references a usable issuer; the key of the
			// provider is removed by the operator
			logger.ContextKV(ctx, xlog.ERROR,
				"reason", "destroy_key",
				"issuer_id", row.ID.UnderscoreString(),
				"key_provider", row.KeyProvider,
				"err", err.Error())
		}
	}
	s.registry.InvalidateIssuer(updated)
	logger.ContextKV(ctx, xlog.NOTICE,
		"status", "issuer_updated",
		"issuer_id", updated.ID.UnderscoreString(),
		"org_id", updated.OrgID.UnderscoreString(),
		"issuer", updated.Label,
		"issuer_status", updated.Status.String())
	events.New(ctx, ServiceName, pb.EventType_IssuerUpdated, "Issuer updated").
		Org(orgID).
		Project(updated.ProjectID).
		Reference(updated.ID).
		Description("issuer %q updated: status %s", updated.Label, updated.Status.String()).
		Emit(s.orgs)
	return issuerPb(ctx, updated)
}

// GetIssuer returns an issuer of the org by ID, by label resolved in the
// project then in the org, or by IKID. An issuer found by ID or IKID must
// be of a project the caller can read, or org-wide (rowAccess).
func (s *Service) GetIssuer(ctx context.Context, req *pb.GetIssuerRequest) (*pb.Issuer, error) {
	if req == nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing request")
	}
	orgID, err := s.tenantOrg(ctx, req.OrgID)
	if err != nil {
		return nil, err
	}
	var row *model.Issuer
	switch {
	case req.ID != "":
		row, err = s.orgIssuer(ctx, orgID, req.ID, pb.CA_GetIssuer_FullMethodName)
	case req.Label != "":
		var projectID xdb.ID
		projectID, err = s.tenantProject(ctx, orgID, req.ProjectID)
		if err != nil {
			return nil, err
		}
		row, err = s.issuerByLabel(ctx, orgID, projectID, req.Label)
	case req.IKID != "":
		row, err = s.db.GetIssuerBySKID(ctx, req.IKID)
		if err != nil {
			if xdb.IsNotFoundError(err) {
				return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "issuer not found")
			}
			return nil, httperror.WrapWithCtx(ctx, err, "unable to find issuer")
		}
		row, err = s.visibleIssuer(ctx, orgID, row, pb.CA_GetIssuer_FullMethodName)
	default:
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "issuer ID, label or IKID is required")
	}
	if err != nil {
		return nil, err
	}
	return issuerPb(ctx, row)
}

// ListIssuers returns the issuers of the org, newest first; a project
// limits the result to its own issuers. Without a project, a member with
// project grants only lists the org-wide issuers and those of its projects.
func (s *Service) ListIssuers(ctx context.Context, req *pb.ListIssuersRequest) (*pb.IssuersResponse, error) {
	if req == nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "missing request")
	}
	orgID, err := s.tenantOrg(ctx, req.OrgID)
	if err != nil {
		return nil, err
	}
	projectID, err := s.tenantProject(ctx, orgID, req.ProjectID)
	if err != nil {
		return nil, err
	}
	cursor, err := listCursor(ctx, req.Cursor)
	if err != nil {
		return nil, err
	}
	q := &query.ListIssuersRequest{
		OrgID:     orgID.UInt64(),
		ProjectID: projectID.UInt64(),
		Status:    req.Status,
		Type:      req.Type,
		Limit:     listLimit(req.Limit),
		Offset:    req.Offset,
		Cursor:    cursor,
	}
	if projectID.IsZero() {
		q.ProjectIDs, err = s.listProjects(ctx, orgID)
		if err != nil {
			return nil, err
		}
	}
	res, err := s.db.ListIssuers(ctx, q)
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "failed to list issuers")
	}
	list, err := res.Pb()
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "invalid issuer config")
	}
	return list, nil
}

// parentIssuer resolves the parent of a new issuer of the scope with the CA
// profile it signs with: an Active issuer visible from the scope, org-wide
// or of the same project as the new issuer (DESIGN.md section 6), or a
// platform issuer that lists the profile in its allowed profiles. An issuer
// of another org or project is not found. The profile is resolved in the
// scope of the parent and must be a CA profile.
func (s *Service) parentIssuer(ctx context.Context, orgID, projectID xdb.ID, parentID, profile string) (*core.Resolution, error) {
	id, err := parseID(ctx, parentID, "parent ID")
	if err != nil {
		return nil, err
	}
	parent, err := s.db.GetIssuer(ctx, id.UInt64())
	if err != nil {
		if xdb.IsNotFoundError(err) {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "parent issuer not found")
		}
		return nil, httperror.WrapWithCtx(ctx, err, "unable to find parent issuer")
	}
	platform := parent.OrgID.IsZero()
	if !platform && parent.OrgID.UInt64() != orgID.UInt64() {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "parent issuer not found")
	}
	if !platform && !parent.ProjectID.IsZero() && parent.ProjectID.UInt64() != projectID.UInt64() {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "parent issuer not found")
	}
	if parent.Status != pb.IssuerStatus_Active {
		return nil, preconditionFailed(ctx, "parent issuer is not active")
	}
	if platform {
		cfg, err := parent.GetConfig()
		if err != nil {
			return nil, httperror.WrapWithCtx(ctx, err, "invalid parent issuer config")
		}
		if !slices.Contains(cfg.AllowedProfiles, profile) {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "profile %q is not allowed by the parent issuer", profile)
		}
	}
	res, err := s.resolve(ctx, parent.OrgID, parent.ProjectID, profile, parent.Label)
	if err != nil {
		return nil, err
	}
	if !res.Profile.CAConstraint.IsCA {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "profile %q is not a CA profile", profile)
	}
	return res, nil
}

// caProfile returns the CA profile of the scope a root signs itself with
func (s *Service) caProfile(ctx context.Context, orgID, projectID xdb.ID, label string) (*authorityProfile, error) {
	row, err := s.registry.FindProfile(ctx, orgID, projectID, label)
	if err != nil {
		if errors.Is(err, core.ErrProfileNotFound) {
			return nil, httperror.NewGrpcFromCtx(ctx, codes.NotFound, "profile not found: %s", label)
		}
		return nil, httperror.WrapWithCtx(ctx, err, "unable to find profile")
	}
	// the row is the registry's, shared with other requests
	profile, err := core.AuthorityProfile(row)
	if err != nil {
		return nil, httperror.WrapWithCtx(ctx, err, "invalid profile")
	}
	if !profile.CAConstraint.IsCA {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "profile %q is not a CA profile", label)
	}
	return profile, nil
}

// issuerError maps a failure to create an issuer: a signing error the
// request causes is the client's, any other is the server's
func (s *Service) issuerError(ctx context.Context, err error) error {
	if isSignRequestError(err) || errors.Is(err, core.ErrSoftwareKeysDisabled) {
		return httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "failed to create issuer: %s", err.Error())
	}
	logger.ContextKV(ctx, xlog.ERROR,
		"reason", "create_issuer",
		"err", err.Error())
	return httperror.WrapWithCtx(ctx, err, "failed to create issuer")
}

// registerIssuer inserts the issuer row, registers the certificate of a
// root as a trust anchor of its org, and drops the stale resolutions of
// its label
func (s *Service) registerIssuer(ctx context.Context, row *model.Issuer) (*model.Issuer, error) {
	registered, err := s.db.RegisterIssuer(ctx, row)
	if err != nil {
		switch {
		case db.IsUniqueViolation(err, db.UniqueIssuerLabel):
			return nil, httperror.NewGrpcFromCtx(ctx, codes.AlreadyExists, "issuer label is already registered: %s", row.Label)
		case db.IsUniqueViolation(err, db.UniqueIssuerSkid):
			return nil, httperror.NewGrpcFromCtx(ctx, codes.AlreadyExists, "issuer key is already registered")
		}
		return nil, httperror.WrapWithCtx(ctx, err, "failed to register issuer")
	}
	if registered.Type == pb.AuthorityType_Root && registered.Pem != "" {
		s.registerRootAnchor(ctx, registered)
	}
	s.registry.InvalidateIssuer(registered)
	return registered, nil
}

// registerRootAnchor registers the certificate of a root issuer as a
// private trust anchor of its org. A failure is logged: the issuer is
// registered, and RegisterRoot is idempotent, so the anchor can be
// registered again.
func (s *Service) registerRootAnchor(ctx context.Context, row *model.Issuer) {
	crt, err := certutil.ParseFromPEM([]byte(row.Pem))
	if err == nil {
		_, err = s.db.RegisterRoot(ctx, model.NewRootCertificate(crt, row.OrgID, pb.Trust_Private, row.Pem))
	}
	if err != nil {
		logger.ContextKV(ctx, xlog.ERROR,
			"reason", "register_root",
			"issuer_id", row.ID.UnderscoreString(),
			"org_id", row.OrgID.UnderscoreString(),
			"err", err.Error())
	}
}
