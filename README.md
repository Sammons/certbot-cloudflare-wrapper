Mounts /app/config.json

```json
{
  "port": "3000",
  "socketPath": "/var/run/docker.sock",
  "email": "test@test.io",
  "domains": [
    "abc.xyz.com"
  ],
  "cloudflareKey": "xyz"
}
```

Individually detects services affected by these domains as it rotates the secrets, and updates them with the new secrets.

Detects that a secret is a domain secret because the tail end of the secret name is the md5sum of the `${domain}.crt` or the `${domain}.pem`,
which is a standardized convention (within sammons modules) to name secrets.

Eventually would like to:
* consider the time of day/load of services as it prepares to impact them, since an update kicks over all of the services
* switch off directly mounting secrets and to using something like hashicorp vault.

For long term persistence, mount `/etc/letsencrypt/live` within this container. Certbot automatically stores keys there.
