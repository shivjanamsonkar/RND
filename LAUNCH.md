# End-to-end launch process

This repository ships a **TCP listener** (`listener.c`) on port **8080**, not an HTTP web server. Clients connect with tools such as `telnet` or `nc` and send line-oriented text; the process logs echoed input. Use the steps below to go from source to a running, reachable service. If you need a **browser-accessible website** (HTML over HTTP), see [Launching an HTTP website](#launching-an-http-website) at the end.

---

## 1. Prerequisites

| Requirement | Notes |
|-------------|--------|
| Linux (or compatible Unix) | Uses POSIX sockets (`sys/socket.h`, etc.). |
| `gcc` | To compile `listener.c`. |
| Network access to the host | For remote clients, the host must allow inbound TCP on the chosen port (default 8080). |

Install a compiler on Debian/Ubuntu:

```bash
sudo apt-get update && sudo apt-get install -y build-essential
```

---

## 2. Get the code

```bash
git clone <repository-url>
cd <repository-directory>
```

Use the branch or tag your team has designated for release (for example `master` or a version tag).

---

## 3. Build

```bash
gcc listener.c -o listener
```

(Optional: `gcc -Wall -Wextra -O2 listener.c -o listener` after adding missing headers such as `<string.h>` in `listener.c`.)

Confirm the binary exists:

```bash
test -x ./listener && echo "Build OK"
```

---

## 4. Run (development)

**Foreground** (logs go to the terminal; stop with Ctrl+C):

```bash
./listener
```

**Background** (same machine):

```bash
./listener &
```

The program binds to **0.0.0.0:8080** (all interfaces). Ensure nothing else is using port 8080:

```bash
ss -tlnp | grep 8080 || true
```

---

## 5. Open the port (production / remote access)

- **Local firewall** (example with `ufw`):

  ```bash
  sudo ufw allow 8080/tcp
  sudo ufw status
  ```

- **Cloud VM** (AWS, GCP, Azure, etc.): add a **security group / firewall rule** allowing **inbound TCP 8080** from the intended client networks only (avoid `0.0.0.0/0` unless you intend a public listener).

- **Docker / Kubernetes**: publish container port 8080 and map it to the host or load balancer as required.

---

## 6. Verify end-to-end

From the **same machine**:

```bash
echo "hello test" | nc -w 2 127.0.0.1 8080
```

Or with `telnet`:

```bash
telnet 127.0.0.1 8080
```

Type a line and press Enter. The **server terminal** should show echoed output and length, matching the logic in `listener.c`.

From a **remote client** (replace with your server’s IP or DNS name):

```bash
echo "remote check" | nc -w 2 <server-host> 8080
```

If this fails, check: process running, firewall, cloud security group, correct IP/DNS, and routing.

---

## 7. Keep it running after logout (optional)

### systemd (Linux)

Create `/etc/systemd/system/pos-listener.service` (adjust `User` and paths):

```ini
[Unit]
Description=POS TCP listener (port 8080)
After=network.target

[Service]
Type=simple
User=nobody
WorkingDirectory=/opt/pos-listener
ExecStart=/opt/pos-listener/listener
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now pos-listener.service
sudo systemctl status pos-listener.service
```

---

## 8. Release checklist (summary)

1. Tag or record the **exact commit** you deploy.  
2. **Build** with the same flags used in CI or release notes.  
3. **Run** on the target host; confirm **one** listener instance owns port 8080.  
4. **Firewall / cloud rules** allow only required sources.  
5. **Smoke test** with `nc` or `telnet` from an allowed client.  
6. **Monitor** process health (systemd, supervisor, or orchestrator) and disk/log rotation if you add file logging later.

---

## Launching an HTTP website

This tree does **not** include HTML, TLS certificates, or an HTTP stack. To launch a **website** (pages in a browser):

1. **Add or host web content** (static HTML/CSS/JS, or an application framework that speaks HTTP).  
2. **Serve HTTP** (for example nginx, Caddy, Apache, or your app’s built-in server) on ports **80/443**.  
3. **TLS**: obtain certificates (e.g. Let’s Encrypt) and terminate HTTPS at the proxy or app.  
4. **DNS**: point your domain’s **A/AAAA** (or **CNAME**) records to the server or CDN.  
5. **CI/CD**: build artifacts in pipeline, run tests, deploy to staging, then production with rollback documented.

If you later add a static `public/` site or a small HTTP server to this repo, extend this document with build commands, the HTTP port, and health-check URLs specific to that implementation.
