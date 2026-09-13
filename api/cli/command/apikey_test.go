package command_test

import (
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

func (s *testSuiteGrpc) Test_APIKeyListCmd() {
	s.MockOrgs.SetResponse(&pb.APIKeysResponse{
		APIKeys: []*pb.APIKey{
			{ID: "555", OrgID: "100", Label: "ci", Key: "sk_100_abc", Scopes: []string{"org:read"}, UsedCount: 2},
		},
	})
	a := command.APIKeyListCmd{}
	s.runPrinted(func() error { return a.Run(s.Ctl) })

	a = command.APIKeyListCmd{Status: "bogus"}
	err := a.Run(s.Ctl)
	s.EqualError(err, "invalid status: bogus")
}

func (s *testSuiteGrpc) Test_APIKeyDeleteCmd() {
	s.MockOrgs.SetResponse(&pb.RecordsResult{Deleted: 1})
	a := command.APIKeyDeleteCmd{ID: "555"}
	s.runPrinted(func() error { return a.Run(s.Ctl) })
}
