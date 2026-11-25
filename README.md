# TLS Appliance Certificate - Morpheus plugin

Issues and renews the TLS certificate of the **Morpheus appliance itself** (the nginx certificate) with Let's
Encrypt. Works on every edition, including **VM Essentials**: it needs no Tasks, Jobs or Reports.

Admin page: `https://<your-manager>/plugin/tls/admin`

- status banner with days remaining, certificate details (subject, issuer, SANs, SHA-256)
- **Check now**, **Renew if due**, **Force renew**
- settings form (domains, e-mail, CA, challenge, DNS provider, token, threshold, auto-renew)
- full log of the last run
- footer badge ("Certificate: 63 days") for users with the permission; hidden for everyone else
- follows the Morpheus user theme (light/dark)

> Status: v0.10.4. Validated on Morpheus 9.1.0-3 on a VM Essentials manager (staging and production issuance via
> DNS-01/Cloudflare, scheduled renewal of a due certificate, and the one-command setup from a clean state). The
> "run the setup through Morpheus" option has been tested end to end (dry run, then a real install including the
> nginx restart) on a manager that is itself a managed instance with an agent.

## How it works

1. Reads the certificate nginx serves (days left, SANs, self-signed or not).
2. Renews when: none/self-signed (the Morpheus default), does not cover the configured domains, forced, or fewer
   days remain than the threshold. The threshold is capped at one third of the certificate lifetime
   (about 30 days for a 90-day certificate), whatever you configure.
3. ACME (acme4j): account key, order, DNS-01 (or HTTP-01), finalize.
4. Backs up the current files to `/etc/morpheus/ssl/backup/<yyyymmddHHMMSS>/{cert,key}.pem` (newest 5 kept),
   writes `/etc/morpheus/ssl/cert.pem` and `key.pem`, and runs `morpheus-ctl restart nginx`.
5. Connects to port 443 and checks that the **new** certificate is really served. If not, it rolls back.

There is **no `morpheus.rb` edit and no `reconfigure`** by the plugin. A timer inside the plugin checks once a day
(first check 2 minutes after the plugin starts) and renews only when due and when "Renew automatically" is on.
Only one run at a time. nginx restarts drop connections, so the page may show "Failed to fetch" for a moment; it
keeps its state and retries.

Settings, the DNS token and the last-run log are stored encrypted in Cypher under
`secret/appliance-tls/{settings,lastrun}`.

## Install

Two steps: upload the plugin, then paste **one command** once on the appliance. No manual file editing.

1. **Upload the plugin:** Administration > Integrations > Plugins > upload
   `morpheus-appliance-tls-<version>-all.jar` (or `POST /api/plugins/upload`, multipart field `plugin`).
2. **Open the admin page** (`/plugin/tls/admin`, System Admin). A "One-time setup needed" card lists what is
   missing and shows a ready-to-paste command with **Copy command** and **View script** buttons. Paste the command in
   a shell on the appliance that can use `sudo` (console or SSH). The card turns green by itself within a few seconds.

   The plugin itself runs without root, so these root-side pieces cannot be installed from the browser; the command
   does them once, idempotently (safe to run again, `--dry-run` shows the plan):
   - installs the privileged helper `/usr/local/sbin/morpheus-tls-helper`: it only touches files below
     `/etc/morpheus/ssl/` (symlinks resolved, `..` refused), only `*.pem`, `*.crt`, `*.key`, only PEM content, modes
     0600/0640/0644, plus `prune N` for the backups. It cannot run commands and cannot reach `morpheus.rb` or the
     secrets file;
   - installs `/etc/sudoers.d/morpheus-tls` for the OS user Morpheus runs as (detected, normally
     `morpheus-app`; checked with `visudo -c` first). It allows exactly two things: the helper and
     `/opt/morpheus/bin/morpheus-ctl restart nginx`;
   - only if nginx is not already using the plugin's files: backs up `/etc/morpheus` to
     `/root/etc-morpheus-backup-<timestamp>.tgz` (mode 0600), copies the certificate nginx serves now to
     `/etc/morpheus/ssl/cert.pem` and `key.pem`, sets `nginx['ssl_certificate']` and `nginx['ssl_server_key']` in
     `/etc/morpheus/morpheus.rb` (backup `morpheus.rb.bak-<timestamp>`) and runs `morpheus-ctl reconfigure`. If that
     fails or nginx still does not use the files, `morpheus.rb` is restored.

   **Alternative, no shell needed:** when the manager is itself a Morpheus-managed Linux server with an agent, the
   card also offers **Run setup** and **Dry run** with a server dropdown (the server with the same IP address as the
   appliance is preselected). Morpheus runs the same script through the agent, as the agent user with `sudo`. This
   needs the separate permission `tlsApplianceSetup` (System Admin has it). A manager that runs outside the cluster
   has no agent; use the command instead.

   The command carries the whole script (gzip + base64), so nothing has to be copied to the appliance first. "View
   script" shows it in readable form and the card prints its SHA-256. The same script is in the release bundle as
   `deploy/morpheus-tls-setup.sh` (`install`, `status`, `uninstall`, `--dry-run`, `--app-user NAME`).
3. **Permission:** feature permission `tlsApplianceCert` (System Admin has it). Only roles with Full access
   see the admin page and the badge.
4. **First run:** enter domain(s) and e-mail, keep the **STAGING** CA, add the Cloudflare API token, Save,
   **Check now** (verifies the DNS credentials), then **Force renew**. When that works, switch to production and
   Force renew again, then tick **Renew automatically**.

Until the checklist is green, Renew if due and Force renew refuse to run ("Setup is not complete"); Check now still
works. The checklist verifies: helper present, sudo may run it, sudo may restart nginx, nginx uses the plugin's
files (read from the rendered `/opt/morpheus/embedded/nginx/conf/sites-available/morpheus-ssl.conf`), and the files
exist. Take a snapshot or backup before the first real run.

### Uninstall

The admin page has the same steps under **Uninstall**, with a copy button for the command in step 2.

1. **Point nginx back to Morpheus' own certificate.** Edit `/etc/morpheus/morpheus.rb` and delete the two lines under
   the comment `# added by morpheus-tls-setup` (`nginx['ssl_certificate']` and `nginx['ssl_server_key']`). If the
   appliance used its own certificate before the setup, restore those lines from `/etc/morpheus/morpheus.rb.bak-*`.
   Then run `sudo morpheus-ctl reconfigure`.
2. **Remove the helper and the sudoers rule:** `sudo bash morpheus-tls-setup.sh uninstall` (the script is in the
   release bundle under `deploy/`). It removes `/etc/sudoers.d/morpheus-tls` and
   `/usr/local/sbin/morpheus-tls-helper` and touches nothing else. `--dry-run` shows what it would do.
3. **Delete the plugin:** Administration > Integrations > Plugins > TLS Appliance Certificate > Delete.
4. **Delete the stored settings in Cypher** (they hold the DNS API token): `secret/appliance-tls/settings` and
   `secret/appliance-tls/lastrun`.
5. **Clean up key material:** `/etc/morpheus/ssl/cert.pem`, `key.pem`, `acme-account.pem` and the `backup/` folder
   there, plus `/root/etc-morpheus-backup-*.tgz` and `/etc/morpheus/morpheus.rb.bak-*`. Do this after step 1, since
   nginx uses `cert.pem` and `key.pem` until then.
6. **Revoke the DNS API token** at your DNS provider.

### Upgrading

Upload the new jar on the Plugins tab (or via the API). Morpheus identifies a plugin by its code (`morpheus-appliance-tls`),
not by the jar file name, so a new version replaces the old one in place. Settings, the DNS token and the last-run log live in
Cypher and survive an upgrade. The root-side setup does not need to be repeated unless the setup card reports the helper as
outdated.

## DNS providers and challenges

- **DNS-01 + Cloudflare** (recommended): API token with Zone > DNS > Edit. The zone is auto-detected (or give the
  zone id). The plugin waits for the TXT record on the authoritative name servers before asking Let's Encrypt to
  validate. Wildcards work with DNS-01.
- **DNS-01 + custom hook script:** an absolute path to an executable called as
  `script add <fqdn> <value>` and `script remove <fqdn> <value>` (no shell; a non-zero exit fails the run).
- **HTTP-01:** needs port 80 reachable from the internet and a free port 80 for the plugin's temporary responder.
  On a normal appliance nginx owns port 80, so prefer DNS-01. Not validated on a real appliance.

## Security notes

Report vulnerabilities privately, see [SECURITY.md](SECURITY.md).

- Least privilege: no broad `sudo`; see the helper and sudoers above. They must be installed by an admin, so a
  plugin upgrade cannot widen its own rights.
- The private key is passed to the helper on stdin and never logged. The ACME account key is
  `/etc/morpheus/ssl/acme-account.pem` (0600).
- The DNS token is stored in Cypher and never shown again (the form shows "saved - leave blank to keep").
- Challenge tokens are validated before they become file names. Plugin POST routes require the Morpheus CSRF token
  and an AJAX header.

## Build

    export JAVA_HOME=/path/to/jdk17
    ./gradlew shadowJar                         # -> build/plugin/morpheus-appliance-tls-<version>-all.jar
    PEBBLE_DIR=~/tools/pebble ./gradlew test    # unit tests + real ACME round trip against a local Pebble CA

Download `pebble` and `pebble-challtestsrv` (release v2.10.x) into `$PEBBLE_DIR/pebble-linux-amd64/linux/amd64/`
and `$PEBBLE_DIR/pebble-challtestsrv-linux-amd64/linux/amd64/`, and clone the pebble repo to `$PEBBLE_DIR/src`.
Without `PEBBLE_DIR` the Pebble tests are skipped.

Compiled against Morpheus plugin API 1.5.0 (Java 11 target, Groovy 3.0.9).

## Layout

    src/main/java/.../core/       renewal engine (plain Java, no Morpheus dependency)
    src/main/groovy/...           Morpheus glue: Plugin, AdminController, SettingsStore, scheduler, runner
    src/main/resources/renderer/  admin page template
    src/assets/                   admin page JS/CSS, footer badge JS/CSS
    deploy/                       privileged helper, sudoers, setup script template (build embeds both into
                                  morpheus-tls-setup.sh, which the admin page serves as the one-line command)
    scripts/SmokeShadowJar.java   full renewal against Pebble using only the built jar

## Known limits

- Only verified on Morpheus 9.1.0-3.
- The one-command setup was tested on one Essentials appliance; the rollback paths (failed reconfigure,
  undetectable app user) are untested.
- Subject/Issuer show the e-mail OID undecoded when present; the Last-run log is not collapsed.

## License

MIT - see [LICENSE](LICENSE). Bundled libraries and their licenses: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). This is an independent project and is not affiliated with or endorsed by HPE, Morpheus Data or Let's Encrypt (ISRG).
