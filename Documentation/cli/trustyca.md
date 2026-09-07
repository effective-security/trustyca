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
                             ~/.config/trustyca. Use TRUSTYCA_STORAGE
                             environment to override
  -H, --http                 Use HTTP client
      --timeout=6            Connection timeout
  -r, --trusted-ca=STRING    Trusted CA store for server TLS

Commands:
  auth providers          print ID providers
  auth login              login to the server
  auth ui                 login to the server via its web login page
  auth claims             print OAuth token claims
  auth usertoken          print user token
  auth revoke             revoke user token
  caller                  print caller info
  caller-ping             ping caller info for duration with intervals
  member list             List members of the org
  member add              Add a new member to the org
  member delete           Delete a member from the org
  member change           Change the role of a member
  member delete-invide    Delete a member invite from the org
  server                  print remote server status
  version                 print remote server version

Run "trustyca <command> --help" for more information on a command.
