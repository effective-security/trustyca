// Package events records audit events for the actions users, API keys and
// the service take on orgs, projects, members and users.
//
// New starts an event with its type, title and the emitting component; the
// builder methods scope it to an org and project, set the referenced entity
// and the details. Emit hands it to a Recorder, such as db.OrgsDb, which
// writes it in the background and logs a failure instead of returning it,
// so emit only after the action it records has succeeded. ParseTimeRange
// validates the time filters of an event list request.
//
//	events.New(ctx, ServiceName, pb.EventType_ProjectCreated, "Project created").
//		Org(orgID).
//		Project(project.ID).
//		Reference(project.ID).
//		Description("project %q created", project.Name).
//		Emit(s.db)
package events
