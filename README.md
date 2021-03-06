Updates docker swarm members managed by sammons/provisioner

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

For long term persistence, mount `/etc/letsencrypt` within this container. Certbot automatically stores keys there.

Exposes a `GET` endpoint `/history` which returns the most recent last 100 entries in the history file (`/app/history/history.txt`)

each entry is an `action`:

```
const action = {
  serviceId: service.ID,
  serviceName,
  oldSecrets,
  newSecrets,
};
```

Runs every 6 hours. Will only kick over services if a new cert is created which would be due to a cert imminently expiring.

Does not check for services that are out of date, it just updates affected services every time it runs, and a new cert is obtained for the given domain.
