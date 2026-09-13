package command

import (
	"time"

	"github.com/effective-security/trustyca/api/client"
	"google.golang.org/protobuf/types/known/emptypb"
)

// VersionCmd prints remote server version
type VersionCmd struct {
}

// Run the command
func (a *VersionCmd) Run(app App) error {
	c, err := app.HTTPClient(true)
	if err != nil {
		return err
	}

	res, err := client.NewHTTPStatusClient(c).Version(app.Context())
	if err != nil {
		return err
	}

	return app.Print(res)
}

// ServerCmd prints remote server status
type ServerCmd struct {
}

// Run the command
func (a *ServerCmd) Run(app App) error {
	c, err := app.HTTPClient(true)
	if err != nil {
		return err
	}

	res, err := client.NewHTTPStatusClient(c).Status(app.Context())
	if err != nil {
		return err
	}

	return app.Print(res)
}

// CallerCmd shows the caller status
type CallerCmd struct {
}

// Run the command
func (a *CallerCmd) Run(app App) error {
	c, err := app.AuthClient(false)
	if err != nil {
		return err
	}

	res, err := c.Caller(app.Context(), &emptypb.Empty{})
	if err != nil {
		return err
	}

	return app.Print(res)
}

// CallerPingCmd shows the caller status
type CallerPingCmd struct {
	Duration int `long:"duration" default:"30" help:"duration in seconds"`
	Interval int `long:"interval" default:"5" help:"interval in seconds"`
}

// Run the command
func (a *CallerPingCmd) Run(app App) error {
	c, err := app.AuthClient(false)
	if err != nil {
		return err
	}

	times := a.Duration / a.Interval

	for i := 0; i < times; i++ {
		res, err := c.Caller(app.Context(), &emptypb.Empty{})
		if err != nil {
			app.Print(err)
		} else {
			app.Print(res)
		}
		time.Sleep(time.Duration(a.Interval) * time.Second)
	}
	return nil
}
