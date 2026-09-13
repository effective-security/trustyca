package main

import (
	"io"
	"os"

	"github.com/alecthomas/kong"
	"github.com/effective-security/trustyca/api/cli/command"
	"github.com/effective-security/trustyca/api/version"
	"github.com/effective-security/trustyca/internal/ctl"
	"github.com/effective-security/trustyca/internal/ctl/admin"
	xctl "github.com/effective-security/x/ctl"
)

type app struct {
	ctl.Cli

	Version command.VersionCmd `cmd:"" help:"print remote server version"`
	Server  command.ServerCmd  `cmd:"" help:"print remote server status"`
	Caller  command.CallerCmd  `cmd:"" help:"print caller info"`
	DpopKey admin.DpopKeysCmd  `cmd:"" help:"DPoP key management"`

	Project admin.OrgCmd `cmd:"" help:"project commands"`
}

func main() {
	realMain(os.Args, os.Stdout, os.Stderr, os.Exit)
}

func realMain(args []string, out io.Writer, errout io.Writer, exit func(int)) {
	cl := app{
		Cli: ctl.Cli{
			Version: xctl.VersionFlag("0.1.1"),
		},
	}
	cl.Cli.WithErrWriter(errout).
		WithWriter(out)

	parser, err := kong.New(&cl,
		kong.Name("trustycactl"),
		kong.Description("CTL tool for trustyca service"),
		//kong.UsageOnError(),
		kong.BindFor[command.App](&cl.Cli),
		kong.BindFor[admin.App](&cl.Cli),
		kong.Writers(out, errout),
		kong.Exit(exit),
		xctl.BoolPtrMapper,
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
		}),
		kong.Vars{
			"version": version.Current().String(),
		})
	if err != nil {
		panic(err)
	}

	ctx, err := parser.Parse(args[1:])
	parser.FatalIfErrorf(err)

	if ctx != nil {
		err = ctx.Run(&cl.Cli)
		ctx.FatalIfErrorf(err)
	}
}
