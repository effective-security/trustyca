package command_test

import (
	"context"

	"github.com/effective-security/trustyca/api/cli/command"
	"github.com/effective-security/trustyca/api/pb"
)

func (s *testSuiteGrpc) Test_APIKeyCreateCmd() {
	s.MockOrgs.SetResponse(&pb.APIKey{
		ID:        "555",
		OrgID:     "100",
		ProjectID: "201",
		Label:     "ci",
		Key:       "sk_100_abc",
		Secret:    "shown-once",
		Scopes:    []string{"certs:issue"},
		ExpiresAt: "2027-01-01T00:00:00Z",
	})
	a := command.APIKeyCreateCmd{Label: "ci", Project: "201", Scopes: []string{"certs:issue"}}
	s.runPrinted(func() error { return a.Run(s.Ctl) })
}

// orgsRecorder records the request of the list of API keys, since the mock
// of the suite answers without keeping it
type orgsRecorder struct {
	pb.OrgsServer
	req *pb.ListAPIKeysRequest
}

func (r *orgsRecorder) ListAPIKeys(_ context.Context, req *pb.ListAPIKeysRequest) (*pb.APIKeysResponse, error) {
	r.req = req
	return &pb.APIKeysResponse{}, nil
}

// orgsApp is the app of the suite with another Orgs client
type orgsApp struct {
	command.App
	orgs pb.OrgsServer
}

func (a orgsApp) OrgsClient() (pb.OrgsServer, error) {
	return a.orgs, nil
}

func (s *testSuiteGrpc) Test_APIKeyListCmd() {
	s.MockOrgs.SetResponse(&pb.APIKeysResponse{
		APIKeys: []*pb.APIKey{
			{ID: "555", OrgID: "100", Label: "ci", Key: "sk_100_abc", Scopes: []string{"org:read"}, UsedCount: 2},
		},
		NextPage: &pb.NextPage{Cursor: "WyIyMDI2LTEwLTMwVDExOjAwOjAwWiIsIjU1NSJd"},
	})
	a := command.APIKeyListCmd{Limit: 1, Cursor: "WyIyMDI2LTEwLTMxVDExOjAwOjAwWiIsIjU1NiJd"}
	s.runPrinted(func() error { return a.Run(s.Ctl) })

	a = command.APIKeyListCmd{Status: "bogus"}
	err := a.Run(s.Ctl)
	s.EqualError(err, "invalid status: bogus")

	// the flags reach the request
	rec := &orgsRecorder{}
	a = command.APIKeyListCmd{Project: "201", Limit: 2, Cursor: "WyJuZXh0Il0"}
	s.Require().NoError(a.Run(orgsApp{App: s.Ctl, orgs: rec}))
	s.Out.Reset()
	s.Require().NotNil(rec.req)
	s.Equal("201", rec.req.ProjectID)
	s.EqualValues(2, rec.req.Limit)
	s.Equal("WyJuZXh0Il0", rec.req.Cursor)
}

func (s *testSuiteGrpc) Test_APIKeyDeleteCmd() {
	s.MockOrgs.SetResponse(&pb.RecordsResult{Deleted: 1})
	a := command.APIKeyDeleteCmd{ID: "555"}
	s.runPrinted(func() error { return a.Run(s.Ctl) })
}
