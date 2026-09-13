package main

import (
	"io"
	"os"

	"github.com/alecthomas/kong"
	"github.com/effective-security/trustyca/api/cli"
	"github.com/effective-security/trustyca/api/cli/command"
	"github.com/effective-security/trustyca/api/version"
	xctl "github.com/effective-security/x/ctl"
)

type app struct {
	cli.Cli

	Auth       command.AuthCmd       `cmd:"" help:"authentication commands"`
	Caller     command.CallerCmd     `cmd:"" help:"print caller info"`
	CallerPing command.CallerPingCmd `cmd:"" help:"ping caller info for duration with intervals"`
	Member     command.MemberCmd     `cmd:"" help:"org scope member commands"`
	Org        command.OrgCmd        `cmd:"" help:"org commands"`
	Server     command.ServerCmd     `cmd:"" help:"print remote server status"`
	Project    command.ProjectCmd    `cmd:"" help:"project commands"`
	APIKey     command.APIKeyCmd     `cmd:"" name:"api-key" help:"API key commands"`
	Version    command.VersionCmd    `cmd:"" help:"print remote server version"`
}

func main() {
	realMain(os.Args, os.Stdout, os.Stderr, os.Exit)
}

func realMain(args []string, out io.Writer, errout io.Writer, exit func(int)) {
	cl := app{
		Cli: cli.Cli{
			Version: xctl.VersionFlag("0.1.1"),
		},
	}
	cl.Cli.WithErrWriter(errout).
		WithWriter(out)

	app := any(&cl.Cli).(command.App)

	parser, err := kong.New(&cl,
		kong.Name("trustyca"),
		kong.Description("CLI tool for trustyca service"),
		//kong.UsageOnError(),
		kong.BindFor[command.App](&cl.Cli),
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
		err = ctx.Run(app)
		ctx.FatalIfErrorf(err)
	}
}
