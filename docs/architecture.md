# Client architecture

## Receive path

Normal operation uses ordinary UDP sockets. The client allocates dynamic primary and
secondary video receiver ports, advertises them with `OPEN_VIDEO`, and receives the
video datagrams directly with `recvfrom()`. Presence sockets use the same approach.

For protocol diagnostics, `--dumpcap` can switch to a packet-capture backend. This is
optional and is not required for preview, LED control, rotation or recording.

Both receive backends feed the same UDP/video parser.

## Threads

The client separates:

- UDP/video reception
- keepalive traffic
- online monitoring
- video watchdog/reopen
- GUI display
- recording

The preview uses a small frame FIFO and a 20 Hz GUI timer. This smooths bursty
frame arrival without allowing unbounded latency.

## Logging

Normal runs intentionally avoid logging every video datagram:

- the first packets are shown for startup diagnostics;
- afterwards only periodic video packet samples are logged;
- JPEG frame information is sampled;
- command responses, errors, NACKs and state changes remain visible.

Run with `--debug` for more protocol details.
