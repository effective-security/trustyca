package command_test

import (
	"net/url"

	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/trustyca/api/cli/command"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/x/netutil"
	"github.com/effective-security/xpki/jwt/dpop"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (s *testSuiteGrpc) TestUserTokenCmd() {
	expectedResponse := &pb.UserTokenResponse{
		Token: &pb.Token{
			TokenType:   "test",
			AccessToken: "at",
			Jkt:         "dpop",
		},
		UserInfo: &pb.UserInfo{
			Email: "denis@ekspand.onmicrosoft.com",
		},
	}
	s.MockAuth.SetResponse(expectedResponse)

	a := command.UserTokenCmd{}

	err := a.Run(s.Ctl)
	s.Require().NoError(err)
	s.CapturePrint()

	s.MockAuth.Err = httperror.NewGrpc(codes.Unknown, "request failed")
	err = a.Run(s.Ctl)
	s.EqualError(err, "unexpected: request failed")
}

func (s *testSuiteGrpc) TestRevokeCmd() {
	s.MockAuth.SetResponse(&emptypb.Empty{})

	a := command.RevokeCmd{}
	s.NoError(a.Run(s.Ctl))

	s.MockAuth.Err = httperror.NewGrpc(codes.Unknown, "request failed")
	s.EqualError(a.Run(s.Ctl), "unexpected: request failed")
}

func (s *testSuiteRest) TestAuthLogin() {
	a := command.LoginCmd{
		NoBrowser: true,
		Provider:  "github",
	}

	err := a.Run(s.Ctl)
	s.Require().NoError(err)
	//s.CapturePrint()
}

func (s *testSuiteRest) TestAuthUI() {
	a := command.UICmd{
		NoBrowser: true,
	}

	err := a.Run(s.Ctl)
	s.Require().NoError(err)

	out := s.Out.String()
	s.Contains(out, "open login URL in browser:")
	s.Contains(out, s.Ctl.Server+"/login?")
	// without the local listener the flow ends on the server's page with a token
	s.Contains(out, "redirect_uri="+url.QueryEscape(s.Ctl.Server+"/authenticated"))
	s.Contains(out, "response_type=token")
	s.Contains(out, "response_mode=fragment")
	s.Contains(out, "nonce=")
}

func (s *testSuiteRest) TestLoginCmd() {
	client, err := s.Ctl.HTTPClient(true)
	s.Require().NoError(err)

	k, err := dpop.GenerateKey("")
	s.Require().NoError(err)

	_, err = client.Config.Storage().SaveKey(k)
	s.Require().NoError(err)

	port, err := netutil.FindFreePort("localhost", 5)
	s.Require().NoError(err)

	a := command.LoginCmd{
		DpopKey:    k.KeyID,
		NoBrowser:  true,
		ListenPort: port,
		Provider:   pb.IDP_Local.DisplayName(),
	}

	/*
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			// allow server to start
			time.Sleep(3 * time.Second)

			u := fmt.Sprintf("http://localhost:%d/login?code=1234", port)
			_, err := http.Get(u)
			s.Require().NoError(err)
		}()
	*/

	err = a.Run(s.Ctl)
	s.EqualError(err, "unsupported provider: choose from: [Google Github]")

	a.Provider = "github"
	err = a.Run(s.Ctl)
	s.Require().NoError(err)

	// wg.Wait()
}
