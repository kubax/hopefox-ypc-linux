# Soulear Linux Camera

Native Linux client for the tested **Soulear/YPC Wi-Fi inspection camera**.

The project grew out of hands-on experimentation with the camera's network
behaviour and a Linux reimplementation of the functions needed for everyday use.

## Features

- live MJPEG preview on Linux
- camera-side LED on/off control
- automatic orientation using the camera's embedded motion metadata
- circular viewport while auto-rotation is active
- local photo capture
- local MKV recording through `ffmpeg`
- stream watchdog / automatic reopen
- camera presence keepalives
- configurable camera, local and broadcast IPv4 addresses
- reduced diagnostic logging suitable for longer sessions

The tested YPC camera produces an actual **480×480 JPEG stream**. Its transport
header advertises 640×480; the client intentionally trusts the JPEG SOF
dimensions instead.

## Requirements

- Linux
- Python 3.10+
- PySide6
- `ffmpeg` for video recording

On Arch Linux, for example:

```bash
sudo pacman -S python-pyside6 ffmpeg
```

`dumpcap` is **optional** and only useful for protocol diagnostics. Normal preview
and control use ordinary UDP sockets and do not require packet-capture privileges.

## Run without installation

```bash
python ./soulear-camera.py
```

Defaults match the tested camera/AP setup:

- local IP: `192.168.1.10`
- camera IP: `192.168.1.1`
- broadcast IP: `192.168.1.255`

Override them when necessary:

```bash
python ./soulear-camera.py \
  --local-ip 192.168.1.20 \
  --camera-ip 192.168.1.1 \
  --broadcast-ip 192.168.1.255
```

See all options:

```bash
python ./soulear-camera.py --help
```

## Install in a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
soulear-camera
```

## Optional packet capture

Normal use does not require a Wi-Fi interface name. For deeper diagnostics you can
optionally switch the receive backend to `dumpcap`:

```bash
soulear-camera --dumpcap
```

The client attempts to determine the correct interface from the route to the camera.
If needed, override it explicitly:

```bash
soulear-camera --dumpcap --interface wlan0
```

## Network model

The camera acts as a Wi-Fi access point. The tested device uses:

| Purpose | Address / port |
|---|---|
| Camera | `192.168.1.1` |
| Tested Linux host | `192.168.1.10` |
| Command/control | UDP `10005` |
| Video open/control | UDP `10006` |
| Notification stream | UDP `10007` |
| Presence | UDP `44506`, `52219`, `52220` |
| Presence broadcast | UDP `46526` |

More detail is in [docs/protocol.md](docs/protocol.md).

## Resolution

The tested YPC backend exposes a 480×480 JPEG image. Extensive testing of
configuration values, alternate open-video subtypes, primary/secondary ports
and the force-open path did not produce another JPEG resolution.

Resolution switching is therefore deliberately **not exposed by this client**.
The GUI reports and records the actual JPEG dimensions instead.

## Development note

This is an experimental hobby project. Most of it was built iteratively through
trial and error with the physical camera, packet observations and AI-assisted
analysis/coding. Expect rough edges, and please report camera revisions that behave
differently.

See [docs/findings.md](docs/findings.md) for the confirmed findings used by the client.
