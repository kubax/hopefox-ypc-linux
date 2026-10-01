# Confirmed findings

## Tested device

The reference device used during development is **Hopefox-branded** and identifies
itself as a YPC camera on the network. Other visually or electronically identical
rebrands may use the same protocol, but they have not yet been individually verified.


This page collects the behaviours that were reproduced reliably on the tested
Hopefox-branded Soulear/YPC-compatible camera used during development and are used by the Linux client.

## Working features

- online/status exchange with the YPC camera
- stable MJPEG reception and JPEG reassembly
- missing-packet NACK handling
- presence/keepalive traffic
- automatic video reopen/watchdog
- LED on/off control
- decoding of the packed orientation metadata
- automatic counter-rotation
- invariant circular viewport
- local still-image saving
- local MKV recording

## Stream dimensions

The transport header reports 640×480 on the tested unit, while the actual JPEG SOF
contains 480×480. The client uses the JPEG dimensions as authoritative.

Attempts to select alternate configured resolutions and alternate stream-open modes
did not produce a second JPEG resolution, so resolution switching is intentionally
not part of the user interface.

## Development approach

The project was developed mostly through iterative trial and error with real hardware,
packet observations, repeated protocol tests and AI-assisted analysis/coding. The
implementation should therefore be treated as practical experimental software rather
than a formal specification of every camera revision.
