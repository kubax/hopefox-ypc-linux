# Client architecture

## Why `dumpcap` is used

The tested camera's network behaviour is not well served by a conventional
single UDP receive socket in every situation. The client therefore opens the
native-style UDP receiver ports expected by the camera while using `dumpcap`
on the selected interface as the canonical packet capture path.

Captured Ethernet/IPv4/UDP packets are parsed in-process and filtered to the
configured camera IP.

## Threads

The client separates:

- raw packet capture
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
