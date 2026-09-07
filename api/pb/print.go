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
}
