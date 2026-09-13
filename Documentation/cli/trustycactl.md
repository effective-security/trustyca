```bash
Usage: trustycactl <command> [flags]

CTL tool for trustyca service

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
  -c, --cert=STRING          Client certificate file for mTLS
  -k, --cert-key=STRING      Client certificate key for mTLS
  -r, --trusted-ca=STRING    Trusted CA store for server TLS

Commands:
  version          print remote server version
  server           print remote server status
  caller           print caller info
  dpop-key gen     generate new key
  dpop-key list    list keys
  project list     list orgs

Run "trustycactl <command> --help" for more information on a command.
```
