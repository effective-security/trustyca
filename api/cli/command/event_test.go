package command_test

import (
	"github.com/effective-security/trustyca/api/cli/command"
	"github.com/effective-security/trustyca/api/pb"
)

func (s *testSuiteGrpc) Test_EventListCmd() {
	s.MockOrgs.SetResponse(&pb.EventsResponse{
		Events: []*pb.Event{
			{
				ID:          "301",
				OrgID:       "100",
				ProjectID:   "201",
				Type:        pb.EventType_ProjectCreated,
				Title:       "Project created",
				Description: `project "Test" created`,
				ReferenceID: "201",
				Email:       "test@example.com",
				Source:      "orgs",
				CreatedAt:   "2026-10-30T12:00:00Z",
			},
			{
				ID:        "300",
				OrgID:     "100",
				Type:      pb.EventType_OrgCreated,
				Title:     "Org created",
				Email:     "test@example.com",
				Source:    "orgs",
				CreatedAt: "2026-10-30T11:00:00Z",
			},
		},
		NextPage: &pb.NextPage{Cursor: "WyIyMDI2LTEwLTMwVDExOjAwOjAwWiIsIjMwMCJd"},
	})
	a := command.EventListCmd{Project: "201", Type: "ProjectCreated", After: "2026-10-01T00:00:00Z", Limit: 10}
	s.runPrinted(func() error { return a.Run(s.Ctl) })

	a = command.EventListCmd{Type: "bogus"}
	err := a.Run(s.Ctl)
	s.EqualError(err, "invalid event type: bogus")
}
