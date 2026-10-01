# Reverse-engineering / interoperability notes

The implementation was developed by observing network traffic and analysing
behaviour necessary to interoperate with a legally obtained camera and client
software.

This repository intentionally contains **no**:

- vendor APK
- extracted native library
- decompiled Java/Kotlin source
- disassembly listing
- copied vendor functions
- proprietary application resources

Only independently written code and protocol descriptions are included.

## Confirmed positive findings

The following behaviours were reproduced successfully on Linux:

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

## Known device limitation

The tested YPC device produces a 480×480 JPEG payload even though the transport
header reports 640×480.

Configuration and alternate-stream experiments did not yield a second
resolution, so this release intentionally contains no resolution-changing UI
or API.
