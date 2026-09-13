```bash
Usage: trustyca <command> [flags]

CLI tool for trustyca service

Flags:
  -h, --help                 Show context-sensitive help.
  -s, --server=STRING        Address of the remote server to connect. Use
                             TRUSTYCA_SERVER environment to override
  -D, --debug                Enable debug mode
      --o=STRING             Print output format: json|yaml
      --cfg="~/.config/trustyca/config.yaml"
                             Configuration file
      --storage=STRING       flag specifies to override default location:
                             ~/.trustyca. Use TRUSTYCA_STORAGE environment to
                             override
  -H, --http                 Use HTTP client
      --timeout=6            Connection timeout
  -r, --trusted-ca=STRING    Trusted CA store for server TLS

Commands:
  auth providers                  print ID providers
  auth login                      login to the server
  auth ui                         login to the server via its web login page
  auth claims                     print OAuth token claims
  auth usertoken                  print user token
  auth revoke                     revoke user token
  auth org                        select the org for the session and store the
                                  new token
  auth allowed                    print allowed methods
  caller                          print caller info
  caller-ping                     ping caller info for duration with intervals
  member list                     List members of the selected org
  member add                      Grant an org-wide role
  member delete                   Remove an org-wide grant
  member change                   Change the org-wide role of a member
  member delete-invite            Delete an org-wide invite
  org create                      create a new org
  org update                      update the selected org
  org delete                      delete the selected org
  org list                        list orgs the user can select
  org get                         get the selected org
  org access                      print the user's access to the selected org
  server                          print remote server status
  project create                  create a new project
  project update                  update a project
  project delete                  delete a project
  project list                    list accessible projects
  project get                     get a project by ID or alias
  project member list             list project grants and invites
  project member add              grant a project role
  project member delete           remove a project grant
  project member change           change the project role of a member
  project member delete-invite    delete a project invite
  version                         print remote server version

Run "trustyca <command> --help" for more information on a command.
```
