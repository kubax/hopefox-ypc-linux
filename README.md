# Soulear Linux Camera

Native Linux client for the tested **Soulear/YPC Wi-Fi inspection camera**.

The project was created by independently documenting the camera's network
behaviour for interoperability. It does **not** contain APK files, native
libraries, decompiled application source, or copied code from the vendor app.

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
- Wireshark `dumpcap`
- `ffmpeg` for video recording

On Arch Linux, for example:

```bash
sudo pacman -S python-pyside6 wireshark-cli ffmpeg
```

`dumpcap` must be usable by the current user. Depending on the distribution,
that may require membership in the `wireshark` group or equivalent capture
permissions.

## Run without installation

```bash
python ./soulear-camera.py
```

Defaults match the tested camera/AP setup:

- interface: `wlp10s0f3u3u1`
- local IP: `192.168.1.10`
- camera IP: `192.168.1.1`
- broadcast IP: `192.168.1.255`

Override them when necessary:

```bash
python ./soulear-camera.py \
  --interface wlan0 \
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

## Legal / interoperability note

This repository documents observed network behaviour and independently
reimplemented interoperability logic. No vendor APK, native library, decompiled
source listing, disassembly, or copied implementation code is included.

See [docs/reverse-engineering-notes.md](docs/reverse-engineering-notes.md).
