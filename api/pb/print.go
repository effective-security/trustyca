package pb

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	sync "sync"
	"time"

	"github.com/effective-security/protoc-gen-go/api"
	"github.com/effective-security/x/format"
	"github.com/effective-security/x/print"
	"github.com/effective-security/x/slices"
	"github.com/effective-security/xdb"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
)

var (
	registerPrintOnce sync.Once
)

func RegisterPrintOnce() {
	// Register here all the custom functions that will be used to print the output of the CLI commands.
	registerPrintOnce.Do(func() {
		api.DefaultDescriber.RegisterEnumNameTypes(EnumNameTypes)

		print.RegisterType(([]*LoginInfo)(nil), PrintLoginInfos)
	})
}

func createTable(w io.Writer) *tablewriter.Table {
	return tablewriter.NewTable(w,
		tablewriter.WithConfig(
			tablewriter.Config{
				Row: tw.CellConfig{
					Formatting: tw.CellFormatting{
						AutoWrap:  tw.WrapTruncate,
						Alignment: tw.AlignLeft,
					},
					ColMaxWidths: tw.CellWidth{Global: 64},
				},
			},
		))
}

func createTableSimple(w io.Writer) *tablewriter.Table {
	return tablewriter.NewTable(w,
		tablewriter.WithRenderer(renderer.NewBlueprint(tw.Rendition{
			Borders: tw.BorderNone,
			//Symbols: tw.NewSymbols(tw.StyleASCII),
			Settings: tw.Settings{
				Separators: tw.Separators{BetweenRows: tw.Off},
				Lines:      tw.Lines{ShowFooterLine: tw.On, ShowHeaderLine: tw.On},
			},
		})),
		tablewriter.WithConfig(
			tablewriter.Config{
				Row: tw.CellConfig{
					Formatting: tw.CellFormatting{
						AutoWrap:  tw.WrapTruncate,
						Alignment: tw.AlignLeft,
					},
					ColMaxWidths: tw.CellWidth{Global: 128},
				},
			},
		))
}

func PrintKVPairs(w io.Writer, header []string, vals []*KVPair) {
	table := createTable(w)

	table.Header(header)
	for _, v := range vals {
		_ = table.Append([]string{v.Key, slices.StringUpto(v.Value, 80)})
	}

	_ = table.Render()
	fmt.Fprintln(w)
}

// PrintLoginInfos prints []*LoginInfo
func PrintLoginInfos(w io.Writer, val any) {
	list := val.([]*LoginInfo)

	table := createTable(w)
	table.Header([]string{"ID", "Name", "Email", "External", "Provider", "Logins", "Last Login"})

	for _, r := range list {
		_ = table.Append([]string{
			r.ID,
			r.Name,
			r.Email,
			r.ExternalID,
			r.Provider.DisplayName(),
			format.Number(r.LoginCount),
			r.LastLoginAt,
		})
	}
	_ = table.Render()
	fmt.Fprintln(w)
}

var dateClaims = map[string]bool{
	"iat":     true,
	"nbf":     true,
	"exp":     true,
	"idp_exp": true,
}

func (r *CallerStatusResponse) Print(w io.Writer) {
	table := createTableSimple(w)
	_ = table.Append([]string{"Subject", r.Subject})
	_ = table.Append([]string{"Role", r.Role})
	_ = table.Render()
	fmt.Fprintln(w)

	claimsTable := createTable(w)
	claimsTable.Header([]string{"Claim", "Value"})

	for _, c := range r.Claims {
		val := c.Value
		if dateClaims[c.Key] && c.Value != "" {
			ux, _ := strconv.ParseInt(c.Value, 10, 64)
			tim := time.Unix(ux, 0).UTC()
			val = format.Time(tim)
		}
		_ = claimsTable.Append([]string{c.Key, val})
	}

	_ = claimsTable.Render()
	fmt.Fprintln(w)
}

func (r *ServerVersion) Print(w io.Writer) {
	fmt.Fprintf(w, "%s (%s)\n", r.Build, r.Runtime)
}

func (r *ServerStatusResponse) Print(w io.Writer) {
	table := createTableSimple(w)
	_ = table.Append([]string{"Name", r.Status.Name})
	_ = table.Append([]string{"Node", r.Status.Nodename})
	_ = table.Append([]string{"Host", r.Status.Hostname})
	_ = table.Append([]string{"Listen URLs", strings.Join(r.Status.ListenUrls, ",")})
	_ = table.Append([]string{"Version", r.Version.Build})
	_ = table.Append([]string{"Runtime", r.Version.Runtime})

	startedAt := xdb.ParseTime(r.Status.StartedAt).UTC()
	uptime := time.Since(startedAt) / time.Second * time.Second
	_ = table.Append([]string{"Started", startedAt.Format(time.RFC3339)})
	_ = table.Append([]string{"Uptime", uptime.String()})
	_ = table.Render()
	fmt.Fprintln(w)

	if len(r.Pods) > 0 {
		print.Map(w, []string{"Service", "Heartbeat"}, r.Pods)
	}
}

func (r *Membership) Print(w io.Writer) {
	table := createTableSimple(w)

	_ = table.Append([]string{"ID", r.ID})
	_ = table.Append([]string{"Org", r.OrgID})
	_ = table.Append([]string{"Org Alias", r.OrgAlias})
	_ = table.Append([]string{"Org Name", r.OrgName})
	_ = table.Append([]string{"Role", r.Role.DisplayName()})
	_ = table.Append([]string{"User", r.UserID})
	_ = table.Append([]string{"Name", r.Name})
	_ = table.Append([]string{"Email", r.Email})
	_ = table.Append([]string{"Created", format.Time(r.CreatedAt)})

	_ = table.Render()
	fmt.Fprintln(w)
}

func (r *Invite) Print(w io.Writer) {
	table := createTableSimple(w)
	_ = table.Append([]string{"ID", r.ID})
	_ = table.Append([]string{"Email", r.Email})
	_ = table.Append([]string{"Role", r.Role.DisplayName()})
	_ = table.Append([]string{"Created", format.Time(r.CreatedAt)})

	_ = table.Render()
	fmt.Fprintln(w)
}

func (r *MembersResponse) Print(w io.Writer) {
	if len(r.Memberships) > 0 {
		fmt.Fprintln(w, "Memberships:")
		PrintMembers(w, r.Memberships)
	}
	if len(r.Invites) > 0 {
		fmt.Fprintln(w, "Invites:")
		PrintInvites(w, r.Invites)
	}
}

func (r *UserMemberships) Print(w io.Writer) {
	PrintMembers(w, r.Memberships)
}

func PrintMembers(w io.Writer, val any) {
	res := val.([]*Membership)
	table := createTable(w)
	table.Header([]string{"Org ID", "Alias", "Org", "Role", "User", "Name", "Email", "Created"})
	for _, membership := range res {
		_ = table.Append([]string{
			membership.OrgID,
			membership.OrgAlias,
			membership.OrgName,
			membership.Role.DisplayName(),
			membership.UserID,
			membership.Name,
			membership.Email,
			format.Time(membership.CreatedAt),
		})
	}
	_ = table.Render()
	fmt.Fprintln(w)
}

func PrintInvites(w io.Writer, val any) {
	res := val.([]*Invite)
	table := createTable(w)
	table.Header([]string{"ID", "Email", "Role", "Created"})
	for _, invite := range res {
		_ = table.Append([]string{
			invite.ID, invite.Email, invite.Role.DisplayName(), format.Time(invite.CreatedAt),
		})
	}
	_ = table.Render()
	fmt.Fprintln(w)
}

func (r *Org) Print(w io.Writer) {
	table := createTableSimple(w)
	_ = table.Append([]string{"ID", r.ID})
	_ = table.Append([]string{"Name", r.Name})
	_ = table.Append([]string{"Alias", r.Alias})
	_ = table.Append([]string{"Status", r.Status.DisplayName()})
	_ = table.Append([]string{"Created", format.Time(r.CreatedAt)})

	_ = table.Render()
	fmt.Fprintln(w)
}

func (r *OrgsResponse) Print(w io.Writer) {
	table := createTable(w)
	table.Header([]string{"ID", "Alias", "Name", "Status", "Created"})
	for _, org := range r.Orgs {
		_ = table.Append([]string{
			org.ID, org.Alias, org.Name, org.Status.DisplayName(), format.Time(org.CreatedAt),
		})
	}
	_ = table.Render()
	fmt.Fprintln(w)
	printNextPage(w, r.NextPage)
}

func (r *UserOrgsResponse) Print(w io.Writer) {
	table := createTable(w)
	table.Header([]string{"ID", "Alias", "Name", "Role", "Role Source", "Explicit Role"})
	for _, access := range r.Orgs {
		_ = table.Append([]string{
			access.OrgID,
			access.OrgAlias,
			access.OrgName,
			access.Role.DisplayName(),
			access.RoleSource.DisplayName(),
			access.ExplicitRole.DisplayName(),
		})
	}
	_ = table.Render()
	fmt.Fprintln(w)
}

func (r *ProjectsResponse) Print(w io.Writer) {
	table := createTable(w)
	table.Header([]string{"ID", "Alias", "Name", "Status", "Created"})
	for _, project := range r.Projects {
		_ = table.Append([]string{
			project.ID, project.Alias, project.Name, project.Status.DisplayName(), format.Time(project.CreatedAt),
		})
	}
	_ = table.Render()
	fmt.Fprintln(w)
	printNextPage(w, r.NextPage)
}

func (r *EventsResponse) Print(w io.Writer) {
	table := createTable(w)
	table.Header([]string{"ID", "Created", "Type", "Project", "Title", "Description", "By", "Source"})
	for _, evt := range r.Events {
		_ = table.Append([]string{
			evt.ID, format.Time(evt.CreatedAt), evt.Type.DisplayName(), evt.ProjectID, evt.Title, evt.Description, evt.Email, evt.Source,
		})
	}
	_ = table.Render()
	fmt.Fprintln(w)
	printNextPage(w, r.NextPage)
}

func (r *Project) Print(w io.Writer) {
	table := createTableSimple(w)
	_ = table.Append([]string{"ID", r.ID})
	_ = table.Append([]string{"Alias", r.Alias})
	_ = table.Append([]string{"Name", r.Name})
	_ = table.Append([]string{"Status", r.Status.DisplayName()})
	_ = table.Append([]string{"Created", format.Time(r.CreatedAt)})

	_ = table.Render()
	fmt.Fprintln(w)
}

func (r *AddMemberResponse) Print(w io.Writer) {
	if r.Membership != nil {
		r.Membership.Print(w)
	}
	if r.Invite != nil {
		r.Invite.Print(w)
	}
}

func (r *Token) Print(w io.Writer) {
	table := createTableSimple(w)
	_ = table.Append([]string{"Token", r.AccessToken})
	_ = table.Append([]string{"Jkt", r.Jkt})
	_ = table.Append([]string{"Issuer", r.Issuer})
	_ = table.Append([]string{"Audience", r.Audience})
	_ = table.Append([]string{"Provider", r.Provider.DisplayName()})
	_ = table.Append([]string{"IssuedAt", format.Time(r.IssuedAt)})
	_ = table.Append([]string{"ExpiresIn", format.Number(r.ExpiresIn)})
	_ = table.Append([]string{"ExpiresAt", format.Time(r.ExpiresAt)})
	_ = table.Render()
	fmt.Fprintln(w)
}

func (r *UserInfo) Print(w io.Writer) {
	table := createTableSimple(w)
	_ = table.Append([]string{"Name", r.Name})
	_ = table.Append([]string{"Email", r.Email})
	_ = table.Append([]string{"EmailVerified", format.YesNo(r.EmailVerified)})
	_ = table.Append([]string{"Role", r.Role})
	_ = table.Append([]string{"Org ID", r.OrgID})
	_ = table.Append([]string{"Org Role", r.OrgRole})
	_ = table.Append([]string{"Org Role Source", r.OrgRoleSource})
	_ = table.Render()
	fmt.Fprintln(w)

	if len(r.Orgs) > 0 {
		print.Map(w, []string{"Org ID", "Role"}, r.Orgs)
	}
}

func (r *UserTokenResponse) Print(w io.Writer) {
	if r.Token != nil {
		r.Token.Print(w)
	}
	if r.UserInfo != nil {
		r.UserInfo.Print(w)
	}
}

func (r *APIKey) Print(w io.Writer) {
	table := createTableSimple(w)
	_ = table.Append([]string{"ID", r.ID})
	_ = table.Append([]string{"Key", r.Key})
	_ = table.Append([]string{"Scopes", strings.Join(r.Scopes, ",")})
	_ = table.Append([]string{"Org ID", r.OrgID})
	_ = table.Append([]string{"Project ID", r.ProjectID})
	_ = table.Append([]string{"Label", r.Label})
	_ = table.Append([]string{"Status", r.Status.DisplayName()})
	_ = table.Append([]string{"Expires At", format.Time(r.ExpiresAt)})
	_ = table.Append([]string{"Used At", format.Time(r.UsedAt)})
	_ = table.Append([]string{"Used Count", format.Number(r.UsedCount)})
	_ = table.Append([]string{"Created", format.Time(r.CreatedAt)})
	_ = table.Render()
	fmt.Fprintln(w)
}

func (r *APIKeysResponse) Print(w io.Writer) {
	table := createTable(w)
	table.Header([]string{"ID", "Org ID", "Project ID", "Label", "Status", "Expires At", "Used At", "Used Count", "Created"})
	for _, apiKey := range r.APIKeys {
		_ = table.Append([]string{
			apiKey.ID,
			apiKey.OrgID,
			apiKey.ProjectID,
			apiKey.Label,
			apiKey.Status.DisplayName(),
			format.Time(apiKey.ExpiresAt),
			format.Time(apiKey.UsedAt),
			format.Number(apiKey.UsedCount),
			format.Time(apiKey.CreatedAt),
		})
	}
	_ = table.Render()
	fmt.Fprintln(w)
}

func (r *CallerScope) Print(w io.Writer) {
	table := createTableSimple(w)
	_ = table.Append([]string{"Org ID", r.OrgID})
	if r.ProjectID != "" {
		_ = table.Append([]string{"Project ID", r.ProjectID})
	}
	_ = table.Append([]string{"Role", r.Role.DisplayName()})
	_ = table.Append([]string{"Role Source", r.RoleSource.DisplayName()})
	_ = table.Append([]string{"Scopes", strings.Join(r.Scopes, ",")})
	_ = table.Append([]string{"Is API Key", format.YesNo(r.IsAPIKey)})
	_ = table.Render()
	fmt.Fprintln(w)

	if len(r.ProjectRoles) > 0 {
		print.Map(w, []string{"Project ID", "Role"}, r.ProjectRoles)
	}
	if len(r.Methods) > 0 {
		PrintMethodAccesses(w, r.Methods)
	}
}

func PrintMethodAccesses(w io.Writer, val any) {
	res := val.([]*MethodAccess)
	table := createTable(w)
	table.Header([]string{"Method", "Allowed", "Allowed Roles", "Scopes"})
	for _, method := range res {
		_ = table.Append([]string{
			method.Method,
			format.YesNo(method.Allowed),
			strings.Join(method.AllowedRoles, ","),
			strings.Join(method.Scopes, ","),
		})
	}
	_ = table.Render()
	fmt.Fprintln(w)
}

// pemOf writes a PEM block of an object after its table, on its own lines
func pemOf(w io.Writer, pem string) {
	if pem != "" {
		fmt.Fprintln(w, strings.TrimSpace(pem))
		fmt.Fprintln(w)
	}
}

func (r *Issuer) Print(w io.Writer) {
	table := createTableSimple(w)
	_ = table.Append([]string{"ID", r.ID})
	_ = table.Append([]string{"Org ID", r.OrgID})
	_ = table.Append([]string{"Project ID", r.ProjectID})
	_ = table.Append([]string{"Label", r.Label})
	_ = table.Append([]string{"Type", r.Type.DisplayName()})
	_ = table.Append([]string{"Status", r.Status.DisplayName()})
	_ = table.Append([]string{"Parent ID", r.ParentID})
	_ = table.Append([]string{"SKID", r.SKID})
	_ = table.Append([]string{"IKID", r.IKID})
	_ = table.Append([]string{"Serial", r.SerialNumber})
	_ = table.Append([]string{"Subject", r.Subject})
	_ = table.Append([]string{"Issuer", r.Issuer})
	_ = table.Append([]string{"SHA-256", r.Sha256})
	_ = table.Append([]string{"Not Before", format.Time(r.NotBefore)})
	_ = table.Append([]string{"Not After", format.Time(r.NotAfter)})
	_ = table.Append([]string{"Key Provider", r.KeyProvider})
	_ = table.Append([]string{"CRL Number", r.CrlNumber})
	if c := r.Config; c != nil {
		_ = table.Append([]string{"AIA URL", c.AiaURL})
		_ = table.Append([]string{"CRL URL", c.CrlURL})
		_ = table.Append([]string{"OCSP URL", c.OcspURL})
		_ = table.Append([]string{"CRL Expiry", c.CrlExpiry})
		_ = table.Append([]string{"CRL Renewal", c.CrlRenewal})
		_ = table.Append([]string{"OCSP Expiry", c.OcspExpiry})
		_ = table.Append([]string{"OCSP Profile", c.DelegatedOcspProfile})
		_ = table.Append([]string{"Allowed Profiles", strings.Join(c.AllowedProfiles, ",")})
	}
	_ = table.Append([]string{"Created", format.Time(r.CreatedAt)})
	_ = table.Append([]string{"Updated", format.Time(r.UpdatedAt)})
	_ = table.Render()
	fmt.Fprintln(w)
	// the CSR of a pending issuer is what the operator takes to the signer
	if r.Status == IssuerStatus_Pending {
		pemOf(w, r.Csr)
	} else {
		pemOf(w, r.Certificate)
	}
}

func (r *IssuersResponse) Print(w io.Writer) {
	table := createTable(w)
	table.Header([]string{"ID", "Org ID", "Project ID", "Label", "Type", "Status", "SKID", "Subject", "Not After"})
	for _, issuer := range r.Issuers {
		_ = table.Append([]string{
			issuer.ID,
			issuer.OrgID,
			issuer.ProjectID,
			issuer.Label,
			issuer.Type.DisplayName(),
			issuer.Status.DisplayName(),
			issuer.SKID,
			issuer.Subject,
			format.Time(issuer.NotAfter),
		})
	}
	_ = table.Render()
	fmt.Fprintln(w)
	printNextPage(w, r.NextPage)
}

func (r *CertProfile) Print(w io.Writer) {
	table := createTableSimple(w)
	_ = table.Append([]string{"ID", r.ID})
	_ = table.Append([]string{"Org ID", r.OrgID})
	_ = table.Append([]string{"Project ID", r.ProjectID})
	_ = table.Append([]string{"Label", r.Label})
	_ = table.Append([]string{"Issuer", r.IssuerLabel})
	_ = table.Append([]string{"Description", r.Description})
	_ = table.Append([]string{"Usages", strings.Join(r.Usages, ",")})
	if c := r.CAConstraint; c != nil && c.IsCA {
		_ = table.Append([]string{"CA", fmt.Sprintf("path length %d", c.MaxPathLen)})
	}
	_ = table.Append([]string{"Expiry", r.Expiry})
	_ = table.Append([]string{"Backdate", r.Backdate})
	_ = table.Append([]string{"Allowed Extensions", strings.Join(r.AllowedExtensions, ",")})
	_ = table.Append([]string{"Allowed Names", r.AllowedNames})
	_ = table.Append([]string{"Allowed DNS", r.AllowedDns})
	_ = table.Append([]string{"Allowed Email", r.AllowedEmail})
	_ = table.Append([]string{"Allowed URI", r.AllowedUri})
	_ = table.Append([]string{"Status", r.Status.DisplayName()})
	_ = table.Append([]string{"Created", format.Time(r.CreatedAt)})
	_ = table.Append([]string{"Updated", format.Time(r.UpdatedAt)})
	_ = table.Render()
	fmt.Fprintln(w)
}

func (r *ProfilesResponse) Print(w io.Writer) {
	table := createTable(w)
	table.Header([]string{"ID", "Org ID", "Project ID", "Label", "Issuer", "Expiry", "Usages", "Status"})
	for _, p := range r.Profiles {
		_ = table.Append([]string{
			p.ID,
			p.OrgID,
			p.ProjectID,
			p.Label,
			p.IssuerLabel,
			p.Expiry,
			strings.Join(p.Usages, ","),
			p.Status.DisplayName(),
		})
	}
	_ = table.Render()
	fmt.Fprintln(w)
	printNextPage(w, r.NextPage)
}

func (r *RootCertificate) Print(w io.Writer) {
	table := createTableSimple(w)
	_ = table.Append([]string{"ID", r.ID})
	_ = table.Append([]string{"Org ID", r.OrgID})
	_ = table.Append([]string{"SKID", r.SKID})
	_ = table.Append([]string{"Subject", r.Subject})
	_ = table.Append([]string{"SHA-256", r.Sha256})
	_ = table.Append([]string{"Trust", r.Trust.DisplayName()})
	_ = table.Append([]string{"Not Before", format.Time(r.NotBefore)})
	_ = table.Append([]string{"Not After", format.Time(r.NotAfter)})
	_ = table.Append([]string{"Created", format.Time(r.CreatedAt)})
	_ = table.Render()
	fmt.Fprintln(w)
	pemOf(w, r.Pem)
}

func (r *RootsResponse) Print(w io.Writer) {
	table := createTable(w)
	table.Header([]string{"ID", "Org ID", "SKID", "Subject", "Trust", "Not After"})
	for _, root := range r.Roots {
		_ = table.Append([]string{
			root.ID,
			root.OrgID,
			root.SKID,
			root.Subject,
			root.Trust.DisplayName(),
			format.Time(root.NotAfter),
		})
	}
	_ = table.Render()
	fmt.Fprintln(w)
	printNextPage(w, r.NextPage)
}

func (r *Certificate) Print(w io.Writer) {
	table := createTableSimple(w)
	_ = table.Append([]string{"ID", r.ID})
	_ = table.Append([]string{"Org ID", r.OrgID})
	_ = table.Append([]string{"Project ID", r.ProjectID})
	_ = table.Append([]string{"Status", r.Status.DisplayName()})
	_ = table.Append([]string{"Profile", r.Profile})
	_ = table.Append([]string{"Label", r.Label})
	_ = table.Append([]string{"Subject", r.Subject})
	_ = table.Append([]string{"Issuer", r.Issuer})
	_ = table.Append([]string{"Serial", r.SerialNumber})
	_ = table.Append([]string{"SKID", r.SKID})
	_ = table.Append([]string{"IKID", r.IKID})
	_ = table.Append([]string{"SHA-256", r.Sha256})
	_ = table.Append([]string{"Not Before", format.Time(r.NotBefore)})
	_ = table.Append([]string{"Not After", format.Time(r.NotAfter)})
	_ = table.Append([]string{"Locations", strings.Join(r.Locations, ",")})
	_ = table.Append([]string{"Created", format.Time(r.CreatedAt)})
	_ = table.Render()
	fmt.Fprintln(w)
	if len(r.Metadata) > 0 {
		print.Map(w, []string{"Metadata", "Value"}, r.Metadata)
	}
	pemOf(w, r.Pem)
}

func (r *CertificateResponse) Print(w io.Writer) {
	if r.Certificate != nil {
		r.Certificate.Print(w)
	}
}

func (r *CertificatesResponse) Print(w io.Writer) {
	table := createTable(w)
	table.Header([]string{"ID", "Org ID", "Project ID", "Status", "Profile", "Subject", "Serial", "IKID", "Not After", "Label"})
	for _, c := range r.Certificates {
		_ = table.Append([]string{
			c.ID,
			c.OrgID,
			c.ProjectID,
			c.Status.DisplayName(),
			c.Profile,
			c.Subject,
			c.SerialNumber,
			c.IKID,
			format.Time(c.NotAfter),
			c.Label,
		})
	}
	_ = table.Render()
	fmt.Fprintln(w)
	printNextPage(w, r.NextPage)
}

func (r *RevokedCertificate) Print(w io.Writer) {
	table := createTableSimple(w)
	_ = table.Append([]string{"Revoked At", format.Time(r.RevokedAt)})
	_ = table.Append([]string{"Reason", r.Reason.DisplayName()})
	_ = table.Append([]string{"Reason Text", r.ReasonText})
	_ = table.Render()
	fmt.Fprintln(w)
	if r.Certificate != nil {
		r.Certificate.Print(w)
	}
}

func (r *RevokedCertificateResponse) Print(w io.Writer) {
	if r.Revoked != nil {
		r.Revoked.Print(w)
	}
}

func (r *RevokedCertificatesResponse) Print(w io.Writer) {
	table := createTable(w)
	table.Header([]string{"ID", "Org ID", "Project ID", "Subject", "Serial", "IKID", "Revoked At", "Reason"})
	for _, rc := range r.RevokedCertificates {
		c := rc.Certificate
		if c == nil {
			c = &Certificate{}
		}
		_ = table.Append([]string{
			c.ID,
			c.OrgID,
			c.ProjectID,
			c.Subject,
			c.SerialNumber,
			c.IKID,
			format.Time(rc.RevokedAt),
			rc.Reason.DisplayName(),
		})
	}
	_ = table.Render()
	fmt.Fprintln(w)
	printNextPage(w, r.NextPage)
}

func (r *Crl) Print(w io.Writer) {
	table := createTableSimple(w)
	_ = table.Append([]string{"ID", r.ID})
	_ = table.Append([]string{"Org ID", r.OrgID})
	_ = table.Append([]string{"Issuer ID", r.IssuerID})
	_ = table.Append([]string{"IKID", r.IKID})
	_ = table.Append([]string{"Number", r.Number})
	_ = table.Append([]string{"Issuer", r.Issuer})
	_ = table.Append([]string{"This Update", format.Time(r.ThisUpdate)})
	_ = table.Append([]string{"Next Update", format.Time(r.NextUpdate)})
	_ = table.Append([]string{"Locations", strings.Join(r.Locations, ",")})
	_ = table.Render()
	fmt.Fprintln(w)
	pemOf(w, r.Pem)
}

func (r *CrlResponse) Print(w io.Writer) {
	if r.Crl != nil {
		r.Crl.Print(w)
	}
}

func (r *CrlsResponse) Print(w io.Writer) {
	table := createTable(w)
	table.Header([]string{"ID", "Org ID", "Issuer ID", "IKID", "Number", "Issuer", "This Update", "Next Update"})
	for _, crl := range r.Crls {
		_ = table.Append([]string{
			crl.ID,
			crl.OrgID,
			crl.IssuerID,
			crl.IKID,
			crl.Number,
			crl.Issuer,
			format.Time(crl.ThisUpdate),
			format.Time(crl.NextUpdate),
		})
	}
	_ = table.Render()
	fmt.Fprintln(w)
}

func (r *SummaryResponse) Print(w io.Writer) {
	table := createTableSimple(w)
	_ = table.Append([]string{"At", format.Time(r.At)})
	for _, c := range r.Issuers {
		_ = table.Append([]string{"Issuers " + c.Status.DisplayName(), strconv.FormatUint(uint64(c.Count), 10)})
	}
	for _, c := range r.Certificates {
		_ = table.Append([]string{"Certificates " + c.Status.DisplayName(), strconv.FormatUint(uint64(c.Count), 10)})
	}
	for _, b := range r.Expiring {
		_ = table.Append([]string{fmt.Sprintf("Expiring within %d days", b.Days), strconv.FormatUint(uint64(b.Count), 10)})
	}
	if r.Crls != nil {
		_ = table.Append([]string{"CRL issuers", strconv.FormatUint(uint64(r.Crls.Issuers), 10)})
		_ = table.Append([]string{"CRLs current", strconv.FormatUint(uint64(r.Crls.Current), 10)})
		_ = table.Append([]string{"CRLs due", strconv.FormatUint(uint64(r.Crls.Due), 10)})
		_ = table.Append([]string{"CRLs overdue", strconv.FormatUint(uint64(r.Crls.Overdue), 10)})
		_ = table.Append([]string{"CRLs missing", strconv.FormatUint(uint64(r.Crls.Missing), 10)})
	}
	_ = table.Render()
	fmt.Fprintln(w)
}

func (r *IssuerInfo) Print(w io.Writer) {
	table := createTableSimple(w)
	_ = table.Append([]string{"Label", r.Label})
	_ = table.Append([]string{"Type", r.Type.DisplayName()})
	_ = table.Append([]string{"Status", r.Status.DisplayName()})
	_ = table.Append([]string{"SKID", r.SKID})
	_ = table.Append([]string{"Subject", r.Subject})
	_ = table.Append([]string{"Not Before", format.Time(r.NotBefore)})
	_ = table.Append([]string{"Not After", format.Time(r.NotAfter)})
	_ = table.Append([]string{"AIA URL", r.AiaURL})
	_ = table.Append([]string{"CRL URL", r.CrlURL})
	_ = table.Append([]string{"OCSP URL", r.OcspURL})
	_ = table.Render()
	fmt.Fprintln(w)
	pemOf(w, r.Certificate)
}

func (r *CertificateStatusResponse) Print(w io.Writer) {
	table := createTableSimple(w)
	_ = table.Append([]string{"IKID", r.IKID})
	_ = table.Append([]string{"Serial", r.SerialNumber})
	_ = table.Append([]string{"Status", r.Status.DisplayName()})
	_ = table.Append([]string{"Not After", format.Time(r.NotAfter)})
	if r.Status == CertificateStatus_Revoked {
		_ = table.Append([]string{"Revoked At", format.Time(r.RevokedAt)})
		_ = table.Append([]string{"Reason", r.Reason.DisplayName()})
	}
	_ = table.Render()
	fmt.Fprintln(w)
}

// printNextPage prints the cursor of the next page of a list, when there is
// one
func printNextPage(w io.Writer, next *NextPage) {
	if next == nil {
		return
	}
	if next.Cursor != "" {
		fmt.Fprintf(w, "Next page: --cursor %s\n\n", next.Cursor)
		return
	}
	fmt.Fprintf(w, "Next page: --offset %d\n\n", next.Offset)
}
