# Confirmed network protocol

This document contains only protocol behaviour confirmed against the tested
Soulear/YPC camera. It is an interoperability description, not vendor source
code.

## Packet framing

Commands use little-endian fields and begin with:

| Offset | Size | Meaning |
|---:|---:|---|
| 0 | 4 | magic `0xFFEEFFEE` |
| 4 | 2 | sequence number |
| 6 | 4 | command ID |
| 10 | 2 | payload length / response status field |
| 12 | n | payload |

The same sequence number is returned in command responses.

## Confirmed command IDs

| Command | ID | UDP port | Purpose |
|---|---:|---:|---|
| CHECK_ONLINE | `0x00010001` | 10005 | status / presence check |
| OPEN_VIDEO | `0x00010004` | 10006 | start/redirect normal video stream |
| LED_STATUS_GET/SET transport | `0x0001000A` | 10005 | illumination state |
| OPEN_VIDEO_FORCE | `0x00010016` | 10006 | force/redirect video stream |
| SET_TIME | `0x0001001A` | 10005 | camera time when supported |
| NACK | `0x0000000B` | 10005 | request retransmission of missing video packets |

## CHECK_ONLINE

The tested device returns a 128-byte status payload. Its identifying status
starts with `YPC`, which is useful when distinguishing this camera family from
other devices supported by generic camera libraries.

## OPEN_VIDEO

The working normal request advertises a dynamically allocated local UDP port.
Subtype `2` is used for normal operation.

The camera then sends proprietary video packets to that local UDP port.

## Video packet header

The video datagram begins with a 16-byte proprietary header followed by a JPEG
fragment.

Confirmed fields:

| Offset | Size | Meaning |
|---:|---:|---|
| 0 | 1 | stream/type value |
| 1 | 1 | packet sequence (wraps at 255) |
| 2 | 1 | frame ID (wraps at 255) |
| 3 | 1 | flags; bit 0 marks last fragment |
| 6 | 4 | packed orientation metadata |
| 12 | 2 | transport width, little-endian |
| 14 | 2 | transport height, little-endian |

On the tested camera the transport dimensions are 640×480 while the actual
JPEG SOF reports **480×480**. The JPEG dimensions are authoritative.

### Reassembly

JPEG data starts after the 16-byte header. Fragments are collected by frame ID
and packet sequence until the last-fragment flag is seen.

Missing packet sequences can be requested through the confirmed NACK command.

## LED

The tested camera uses command `0x0001000A` with a three-byte payload.

Confirmed payloads:

| Action | Payload |
|---|---|
| off | `11 00 00` |
| on | `11 01 64` |

The first byte contains the operation type (`1`) combined with the SET marker.
The second byte is the LED state and the third is the light value.

The physical LED may react with a small delay.

## Presence / keepalive traffic

The following traffic was required to reproduce stable vendor-like presence
behaviour:

| Local port | Destination | Payload | Approx. cadence |
|---:|---|---|---|
| 52220 | broadcast:46526 | `66 30 01 01` | ~1 s |
| 52219 | camera:52219 | `86 06 01` | ~1 s |
| 44506 | camera:44506 | `20 36` | ~3 s |

The client also sends an initial related presence probe to the camera network.

## Notification channel

The camera emits status/notification traffic associated with UDP 10007. The
client records useful metadata but does not require interpretation of every
notification field for preview operation.

## Local recording

The camera stream itself is JPEG. The Linux client feeds complete JPEG frames
to `ffmpeg` and creates a local MKV file.

The tested YPC camera did not require a separate high-resolution capture path;
recording uses the same live JPEG frames shown by the preview.
