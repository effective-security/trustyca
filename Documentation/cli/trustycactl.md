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
  version                print remote server version
  server                 print remote server status
  caller                 print caller info
  dpop-key gen           generate new key
  dpop-key list          list keys
  org list               list orgs
  project list           list projects
  ca issuer list         list the issuers of every org, of the platform or of an
                         org
  ca issuer get          get an issuer of an org by ID, label or key identifier
  ca issuer register     create an issuer: a self-signed root, one signed by a
                         parent, or a pending one with a CSR
  ca issuer import       import an issuer from its certificate and key
  ca issuer activate     activate a pending issuer with its externally signed
                         certificate
  ca issuer archive      archive an active issuer: it signs nothing new but
                         still serves CRL and OCSP
  ca issuer destroy      destroy the key of an archived issuer
  ca profile list        list the profiles of an org
  ca profile get         get a profile of an org by ID or label
  ca profile register    create or replace a profile of an org from a YAML file
  ca profile delete      delete a profile of an org
  ca root list           list the trust anchors of an org, or of the platform
  ca root register       register a self-signed CA certificate as a trust anchor
                         of an org
  ca cert list           list the certificates of every org, of the platform or
                         of an org
  ca cert get            get a certificate of an org by ID, key identifier,
                         thumbprint or issuer and serial
  ca cert revoke         revoke a certificate of an org
  ca crl get             get the current CRL of an issuer
  ca crl publish         publish the CRL of an issuer, or the due CRLs of the
                         issuers in scope
  ca org bootstrap       onboard an org: register its first issuing CA under a
                         platform issuer and copy the template profiles
  ca summary             the counts of the issuers, certificates and CRLs of an
                         org

Run "trustycactl <command> --help" for more information on a command.
```
