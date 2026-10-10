# Set the diagnostic MAC address (required for telnet unlock)

ZTE ONT devices only open the factory telnet port for a client whose **network card MAC equals `00:07:29:55:35:57`** (the diagnostic address embedded in ZTE's factory tooling). ZUDZ checks this before unlocking and refuses with exact fix commands otherwise — without it the factory protocol completes but port 23 stays silently filtered.

The change is temporary with method 1 (reverts on reboot) and persistent with methods 2–4.

## 1. Find your interface name and current MAC

```bash
ip route get 192.168.1.1     # → "dev <iface>" is your wired interface
ip link show <iface> | grep ether
```

## 2. Change it (pick one method)

### `ip` (temporary — reverts on reboot)

```bash
sudo ip link set dev <iface> down
sudo ip link set dev <iface> address 00:07:29:55:35:57
sudo ip link set dev <iface> up
```

### NetworkManager (persistent — the Linux equivalent of the Windows "Locally Administered Address" setting)

```bash
nmcli connection show                       # find your wired connection name
nmcli connection modify "<name>" ethernet.cloned-mac-address 00:07:29:55:35:57
nmcli connection down "<name>" && nmcli connection up "<name>"
```

Or via the GUI: **Settings → Network → gear icon → Identity → Cloned Address** → `00:07:29:55:35:57` → Apply, then toggle the connection.

### `macchanger`

```bash
sudo ip link set dev <iface> down
sudo macchanger -m 00:07:29:55:35:57 <iface>
sudo ip link set dev <iface> up
```

### systemd-networkd (servers, persistent)

Create `/etc/systemd/network/10-mac.link`:

```ini
[Match]
OriginalName=<iface>

[Link]
MACAddress=00:07:29:55:35:57
```

Then reboot.

## 3. Verify

```bash
ip link show <iface>    # must show: link/ether 00:07:29:55:35:57
```

## Reverting

| Method | Revert |
|---|---|
| `ip` | reboot |
| NetworkManager | `nmcli connection modify "<name>" ethernet.cloned-mac-address ""` |
| macchanger | `sudo macchanger -p <iface>` |
| systemd-networkd | delete `10-mac.link` and reboot |

## Troubleshooting

- **`Cannot assign requested address`** — the first byte must be even (`00` here, so the address itself is fine); make sure the interface exists.
- **MAC reverts after a moment** — NetworkManager resets it; use the NetworkManager method instead of `ip`.
- **`Operation not permitted`** — use `sudo`.

> **Note:** the web UI path (scraping, config export + decryption) works over HTTP and does **not** require this change — only the telnet-based operations (unlock, extract-all, region change, GPON read/write) do.
