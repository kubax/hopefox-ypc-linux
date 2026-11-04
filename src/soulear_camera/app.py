"""Qt application and camera protocol implementation for the Hopefox YPC client."""

import argparse
import logging
import math
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import deque
from collections.abc import Iterator, Sequence
from contextlib import suppress
from importlib.metadata import version
from typing import IO, Literal

from PySide6.QtCore import (
    QBuffer,
    QByteArray,
    QIODevice,
    QObject,
    QRectF,
    Qt,
    QTimer,
    Signal,
)
from PySide6.QtGui import QCloseEvent, QImage, QPainter, QPainterPath, QPixmap, QResizeEvent
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

__version__ = version("hopefox-ypc-linux")

# ======================================================================
# Soulear protocol constants (confirmed/documented behaviour)
# ======================================================================

MAGIC = 0xFFEEFFEE

CMD_CHECK_ONLINE = 0x00010001
CMD_OPEN_VIDEO = 0x00010004  # internal proOpenVideo (normal stream)
CMD_OPEN_VIDEO_FORCE = 0x00010016  # exported openVideoForceApi
CMD_SET_TIME = 0x0001001A
CMD_RECORD_STATUS_SYNC = 0x0001001B  # native proRecordStatusSync
CMD_NACK = 0x0000000B
CMD_LED_STATUS_GET = 0x0001000A
CMD_LED_STATUS_SET = 0x0001000A  # native LedStatusSet reuses LedStatusGet wire helper

CAMERA_CONTROL_PORT = 10005
CAMERA_VIDEO_COMMAND_PORT = 10006

PRESENCE_VIDEO_PORT = 44506
PRESENCE_CONTROL1_PORT = 52219
PRESENCE_CONTROL2_PORT = 52220
PRESENCE_CONTROL2_DEST = 46526

KEEPALIVE_VIDEO = bytes.fromhex("20 36")
KEEPALIVE_CONTROL1 = bytes.fromhex("86 06 01")
KEEPALIVE_CONTROL2 = bytes.fromhex("66 30 01 01")

VIDEO_HEADER_SIZE = 16
JPEG_SOI = b"\xff\xd8"
JPEG_EOI = b"\xff\xd9"
MAX_JPEG_SIZE = 5 * 1024 * 1024


# ======================================================================
# Qt signals
# ======================================================================


class Signals(QObject):
    """Qt signals used to publish camera frames and UI state across threads."""

    frame = Signal(bytes)
    status = Signal(str)
    stats = Signal(str)
    recording_state = Signal(bool)


class CaptureError(RuntimeError):
    """Report an optional packet-capture setup or decoding failure."""

    def __init__(
        self,
        code: Literal["header", "format", "link", "ip", "interface", "dumpcap", "stdout"],
        detail: str | int | None = None,
    ) -> None:
        """Create a capture error from a stable code and optional detail.

        Parameters
        ----------
        code : Literal["header", "format", "link", "ip", "interface", "dumpcap", "stdout"]
            Failure category used to select the user-facing message.
        detail : str | int | None, optional
            PCAP format or link-type detail for malformed input.
        """
        if code == "header":
            message = "dumpcap lieferte keinen PCAP-Header"
        elif code == "format":
            message = f"Unbekanntes PCAP-Format: {detail}"
        elif code == "link":
            message = f"Unerwarteter PCAP-Linktype {detail}; Ethernet (1) erwartet"
        elif code == "ip":
            message = "ip command not found"
        elif code == "interface":
            message = "dumpcap mode needs a network interface; use --interface"
        elif code == "dumpcap":
            message = "dumpcap not found; install Wireshark CLI or run without --dumpcap"
        else:
            message = "dumpcap stdout fehlt"
        super().__init__(message)


# ======================================================================
# Classic PCAP reader for dumpcap -F pcap -w -
# ======================================================================


class PcapStreamReader:
    """Read classic PCAP records from a binary stream."""

    def __init__(self, stream: IO[bytes]) -> None:
        """Initialize a reader for a binary PCAP stream.

        Parameters
        ----------
        stream : IO[bytes]
            Open stream positioned at the PCAP global header.
        """
        self.stream = stream
        self.endian: str | None = None
        self.linktype: int | None = None

    def read_exact(self, size: int) -> bytes | None:
        """Read exactly ``size`` bytes, or return ``None`` at end of stream.

        Parameters
        ----------
        size : int
            Number of bytes to read.

        Returns
        -------
        bytes | None
            Read data, or ``None`` if the stream ends before any more data.

        Raises
        ------
        OSError
            If the underlying stream cannot be read.
        """
        result = bytearray()
        while len(result) < size:
            chunk = self.stream.read(size - len(result))
            if not chunk:
                return None
            result.extend(chunk)
        return bytes(result)

    def read_global_header(self) -> str:
        """Validate the PCAP global header and return its byte order.

        Returns
        -------
        str
            ``"<"`` for little-endian records or ``">"`` for big-endian records.

        Raises
        ------
        CaptureError
            If the header is missing, has an unsupported magic value, or does not use Ethernet.
        OSError
            If the underlying stream cannot be read.
        """
        header = self.read_exact(24)
        if header is None:
            raise CaptureError("header")

        magic = header[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
        else:
            raise CaptureError("format", magic.hex(" "))

        self.endian = endian
        _, _, _, _, _, self.linktype = struct.unpack(endian + "HHIIII", header[4:24])
        if self.linktype != 1:
            raise CaptureError("link", self.linktype)
        return endian

    def packets(self) -> Iterator[bytes]:
        """Yield packet records after validating the global header.

        Returns
        -------
        Iterator[bytes]
            Captured Ethernet frames in file order.

        Raises
        ------
        CaptureError
            If the global header is invalid.
        OSError
            If the underlying stream cannot be read.
        """
        endian = self.read_global_header()
        while True:
            packet_header = self.read_exact(16)
            if packet_header is None:
                return
            _, _, captured_len, _ = struct.unpack(endian + "IIII", packet_header)
            packet = self.read_exact(captured_len)
            if packet is None:
                return
            yield packet


# ======================================================================
# Soulear client
# ======================================================================


class SoulearCamera:
    """Manage camera UDP communication, JPEG reassembly, and local recording."""

    def __init__(
        self,
        interface: str | None,
        use_dumpcap: bool,
        local_ip: str,
        camera_ip: str,
        broadcast_ip: str,
        signals: Signals,
        debug: bool = False,
        keepalives: bool = True,
        online_monitor: bool = True,
        fallback_force: bool = True,
        auto_reopen: bool = True,
    ) -> None:
        """Initialize camera configuration and runtime state.

        Parameters
        ----------
        interface : str | None
            Optional network interface used by dumpcap capture.
        use_dumpcap : bool
            Select dumpcap instead of native UDP receive sockets.
        local_ip : str
            Local IPv4 address to bind for camera communication.
        camera_ip : str
            Camera IPv4 address.
        broadcast_ip : str
            IPv4 broadcast destination for presence packets.
        signals : Signals
            Qt signals used to publish frames and status updates.
        debug : bool, optional
            Enable verbose protocol diagnostics.
        keepalives : bool, optional
            Enable camera-presence packets.
        online_monitor : bool, optional
            Enable periodic online checks.
        fallback_force : bool, optional
            Try the force-open command when the normal stream does not start.
        auto_reopen : bool, optional
            Reopen the stream after an extended packet stall.
        """
        self.interface = interface
        self.use_dumpcap = bool(use_dumpcap)
        self.local_ip = local_ip
        self.camera_ip = camera_ip
        self.broadcast_ip = broadcast_ip
        self.signals = signals
        self.debug = debug
        self.logger = logging.getLogger(__name__)
        self.keepalives_enabled = keepalives
        self.online_monitor_enabled = online_monitor
        self.fallback_force = fallback_force
        self.auto_reopen = auto_reopen

        self.running = False
        self.camera_connected = False
        self.reconfiguring = False
        self.seq_lock = threading.Lock()
        self.protocol_sequence = 1
        self.command_lock = threading.Lock()
        self.packet_process_lock = threading.Lock()

        # The camera sends video to dynamically allocated UDP ports advertised
        # by OPEN_VIDEO. Normal operation uses ordinary UDP recvfrom() sockets.
        # dumpcap is available only as an optional diagnostic capture backend.
        self.video_socket = None
        self.video2_socket = None
        self.video_port = 0
        self.video2_port = 0

        self.presence_video_socket = None
        self.presence_control1_socket = None
        self.presence_control2_socket = None

        self.dumpcap_process = None
        self.capture_thread = None
        self.receiver_threads = []
        self.keepalive_thread = None
        self.online_thread = None
        self.watchdog_thread = None

        self.first_video_event = threading.Event()
        self.last_video_packet_time = None
        self.last_open_time = 0.0
        self.last_reopen_time = 0.0
        self.normal_open_acked = False
        self.force_open_used = False

        self.status_payload = None
        self.capabilities_byte = 0
        self.dual_stream = False

        # JPEG reassembly
        self.jpeg_lock = threading.Lock()
        self.jpeg_buffer = bytearray()
        self.collecting_jpeg = False
        self.current_frame_id = None
        self.expected_packet_sequence = None
        self.current_width = 0
        self.current_height = 0
        self.current_camera_angle = None

        # Stats
        self.raw_packet_count = 0
        self.video_packet_count = 0
        self.video_log_every = 100
        self.jpeg_log_every = 25
        self._last_logged_jpeg_resolution = None
        self.control_packet_count = 0

        # Diagnostics
        self.notify_packet_count = 0
        self.stale_video_count = 0
        self._last_stale_log_time = 0.0
        self._last_stale_port = None
        self._packet_loss_events = 0
        self._last_packet_loss_log_time = 0.0

        #  NE7-compatible legacy 44506 JPEG stream
        self.legacy_frame_number = None
        self.legacy_chunks = {}
        self.legacy_last_chunk = None
        self.legacy_packet_count = 0
        self.legacy_frame_count = 0

        #  real camera RecordStatusSync + local video capture
        self.camera_recording = False
        self.record_remote_active = False
        self.record_remote_error = None
        self.record_start_resolution = None
        self.record_seen_resolutions = set()
        self.record_frame_count = 0
        self.record_output_path = None
        self.record_ffmpeg = None
        self.record_lock = threading.Lock()
        self.record_fps = 20
        self.record_auto_rotate = False

        self.frame_count = 0
        self.dropped_frames = 0
        self.nack_count = 0
        self.last_jpeg = None
        self.last_jpeg_angle = None

        # Track the actual dimensions encoded in the JPEG SOF marker.
        # The proprietary transport header advertises 640x480 on the tested
        # YPC device while the JPEG payload itself is 480x480.
        self.last_jpeg_resolution = None
        self.last_transport_resolution = None

        #  recording-style preview buffer.
        # The camera delivers frames with noticeable timing jitter (~16-17 fps).
        # Instead of showing them immediately, the GUI plays a small FIFO at a
        # fixed 20 Hz, exactly like the successful MJPEG recording timeline.
        self.gui_frame_lock = threading.Lock()
        self.gui_frame_queue = deque(maxlen=12)
        self.gui_last_frame = None
        self.gui_preview_started = False
        self.gui_preview_target_buffer = 4
        self.gui_preview_max_latency_frames = 8

        #  camera-side light control and per-frame gyro angle.
        # APK closeOrOpenDeviceLed(boolean):
        #   opType=1
        #   ON : ledStatus=1, lightValue=100
        #   OFF: ledStatus=0, lightValue=0
        self.led_status = None
        self.led_value = None
        self.led_op_type = None

        self.auto_rotate = False
        self.last_camera_angle = None  # filtered absolute angle
        self.raw_camera_angle = None
        self.auto_rotate_zero = None  # angle at enable time
        self.angle_reject_count = 0
        self.angle_filter_alpha = 0.35
        self.angle_max_step = 20.0
        self.angle_reject_jump = 75.0
        self.gyro_packet_count = 0
        self.gyro_xyz = None

        # RX FPS is measured over a real time window instead of smoothing
        # per-frame intervals (UDP delivery can arrive in short bursts).
        self.fps_window_start = None
        self.fps_window_frames = 0
        self.fps_average = 0.0

    # ------------------------------------------------------------------
    # Logging / sequence
    # ------------------------------------------------------------------

    def next_sequence(self) -> int:
        """Return the next nonzero 16-bit protocol sequence number.

        Returns
        -------
        int
            Sequence number reserved under the sequence lock.
        """
        with self.seq_lock:
            value = self.protocol_sequence
            self.protocol_sequence = (self.protocol_sequence + 1) & 0xFFFF
            if self.protocol_sequence == 0:
                self.protocol_sequence = 1
            return value

    # ------------------------------------------------------------------
    # Sockets
    # ------------------------------------------------------------------

    def make_dynamic_socket(self) -> socket.socket:
        """Create a timed UDP socket bound to an ephemeral local port.

        Returns
        -------
        socket.socket
            Bound datagram socket for receiving camera traffic.

        Raises
        ------
        OSError
            If socket creation or binding fails.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.local_ip, 0))
        sock.settimeout(0.2)
        return sock

    def make_bound_broadcast_socket(self, port: int) -> socket.socket:
        """Create a broadcast-enabled UDP socket bound to ``port``.

        Parameters
        ----------
        port : int
            Local UDP port to bind.

        Returns
        -------
        socket.socket
            Bound broadcast datagram socket.

        Raises
        ------
        OSError
            If socket creation or binding fails.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind((self.local_ip, port))
        sock.settimeout(0.2)
        return sock

    def create_native_sockets(self) -> None:
        """Create the dynamic video sockets and optional presence sockets.

        Raises
        ------
        OSError
            If either required video socket cannot be created or bound.
        """
        self.video_socket = self.make_dynamic_socket()
        self.video2_socket = self.make_dynamic_socket()
        self.video_port = self.video_socket.getsockname()[1]
        self.video2_port = self.video2_socket.getsockname()[1]

        self.logger.info(f"UDP video receivers ready on ports {self.video_port} and {self.video2_port}")

        if self.keepalives_enabled:
            try:
                self.presence_video_socket = self.make_bound_broadcast_socket(PRESENCE_VIDEO_PORT)
                self.presence_control1_socket = self.make_bound_broadcast_socket(PRESENCE_CONTROL1_PORT)
                self.presence_control2_socket = self.make_bound_broadcast_socket(PRESENCE_CONTROL2_PORT)
                self.logger.info("Presence sockets:     44506, 52219, 52220")
            except OSError as exc:
                self.logger.warning(f"Presence sockets unavailable: {exc}")
                self.keepalives_enabled = False

    def _build_synthetic_udp_frame(self, src_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
        """Wrap a UDP datagram in the Ethernet/IP format expected by the parser.

        Parameters
        ----------
        src_ip : str
            Source IPv4 address.
        src_port : int
            Source UDP port.
        dst_port : int
            Destination UDP port.
        payload : bytes
            UDP payload to wrap.

        Returns
        -------
        bytes
            Synthetic Ethernet frame using the configured local IP as destination.

        Raises
        ------
        OSError
            If either IPv4 address is invalid.
        """
        udp_len = 8 + len(payload)
        total_len = 20 + udp_len
        ethernet = (b"\x00" * 12) + b"\x08\x00"
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            total_len,
            0,
            0,
            64,
            17,
            0,
            socket.inet_aton(src_ip),
            socket.inet_aton(self.local_ip),
        )
        udp_header = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
        return ethernet + ip_header + udp_header + payload

    def socket_receive_loop(self, sock: socket.socket, local_port: int, label: str) -> None:
        """Receive datagrams from one socket and feed valid camera packets onward.

        Parameters
        ----------
        sock : socket.socket
            UDP socket being serviced.
        local_port : int
            Local destination port represented in the synthetic frame.
        label : str
            Name used in diagnostics for this receiver.
        """
        received_count = 0
        while self.running:
            try:
                payload, address = sock.recvfrom(65535)
            except TimeoutError:
                continue
            except OSError:
                if self.running:
                    self.logger.exception("%s socket receive failed", label)
                return
            except Exception:
                if self.running:
                    self.logger.exception("%s receive error", label)
                return

            received_count += 1
            src_ip, src_port = address[0], address[1]
            self.log_video_socket_sample(label, received_count, local_port, src_ip, src_port, payload)
            if src_ip != self.camera_ip:
                continue
            frame = self._build_synthetic_udp_frame(src_ip, src_port, local_port, payload)
            try:
                with self.packet_process_lock:
                    self.process_ethernet_frame(frame)
            except Exception:
                if self.running:
                    self.logger.exception("%s packet processing failed", label)

    def log_video_socket_sample(
        self, label: str, count: int, local_port: int, src_ip: str, src_port: int, payload: bytes
    ) -> None:
        """Log a small sample of raw video-socket traffic in debug mode."""
        if not (self.debug and label.startswith("video-") and count <= 5):
            return
        self.logger.debug(
            f"UDP RX {label} #{count}: {src_ip}:{src_port} -> "
            f"{self.local_ip}:{local_port} len={len(payload)} "
            f"data={payload[:20].hex(' ')}"
        )

    def start_socket_receivers(self) -> None:
        """Start daemon receiver threads for all available UDP sockets."""
        self.receiver_threads = []
        sockets = [
            (self.video_socket, self.video_port, "video-primary"),
            (self.video2_socket, self.video2_port, "video-secondary"),
            (self.presence_video_socket, PRESENCE_VIDEO_PORT, "presence-44506"),
            (self.presence_control1_socket, PRESENCE_CONTROL1_PORT, "presence-52219"),
            (self.presence_control2_socket, PRESENCE_CONTROL2_PORT, "presence-52220"),
        ]
        for sock, port, label in sockets:
            if sock is None:
                continue
            thread = threading.Thread(
                target=self.socket_receive_loop,
                args=(sock, port, label),
                daemon=True,
            )
            thread.start()
            self.receiver_threads.append(thread)
        self.logger.info("UDP socket capture active")

    # ------------------------------------------------------------------
    # Synchronous native-style command transaction
    # ------------------------------------------------------------------

    def sync_transaction(
        self,
        packet: bytes,
        destination_port: int,
        expected_seq: int,
        timeout: float = 0.15,
        retries: int = 4,
        label: str = "COMMAND",
    ) -> bytes | None:
        """Send a command and wait for a matching protocol response.

        Parameters
        ----------
        packet : bytes
            Serialized command datagram.
        destination_port : int
            Camera UDP port receiving the command.
        expected_seq : int
            Sequence number required in the response.
        timeout : float, optional
            Timeout in seconds for each receive attempt.
        retries : int, optional
            Maximum number of send attempts.
        label : str, optional
            Diagnostic name for the transaction.

        Returns
        -------
        bytes | None
            Matching response, or ``None`` after all attempts time out.

        """
        # cameraRecordStatusSync uses a temporary UDP socket for the sync
        # exchange. Reproduce that behavior rather than retaining a command
        # socket between calls.
        with self.command_lock:
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind((self.local_ip, 0))
                sock.settimeout(timeout)
                local_port = sock.getsockname()[1]

                self.logger.debug(
                    f"{label}: local UDP :{local_port} -> {self.camera_ip}:{destination_port}  {packet.hex(' ')}"
                )

                for attempt in range(1, retries + 1):
                    try:
                        sock.sendto(packet, (self.camera_ip, destination_port))
                        response, address = sock.recvfrom(8192)
                    except TimeoutError:
                        self.logger.debug(f"{label}: timeout {attempt}/{retries}")
                        continue

                    if len(response) < 6:
                        self.logger.debug(f"{label}: short response {response.hex(' ')}")
                        continue

                    magic, seq = struct.unpack_from("<IH", response, 0)
                    if magic != MAGIC or seq != expected_seq:
                        self.logger.debug(f"{label}: unrelated response from {address}: magic=0x{magic:08x} seq={seq}")
                        continue

                    self.logger.debug(
                        f"{label}: ACK/RX {len(response)} bytes from "
                        f"{address[0]}:{address[1]}  {response[:32].hex(' ')}"
                    )
                    return response
            except OSError as exc:
                self.logger.warning("%s UDP transaction failed: %s", label, exc)
                return None
            finally:
                if sock is not None:
                    with suppress(OSError):
                        sock.close()

        return None

    # ------------------------------------------------------------------
    # cameraCheckOnline (0x00010001 -> UDP 10005)
    # ------------------------------------------------------------------

    def camera_check_online(self, quiet: bool = False) -> bool:
        """Query camera availability and cache a valid capability block.

        Parameters
        ----------
        quiet : bool, optional
            Suppress routine status messages when true.

        Returns
        -------
        bool
            Whether the camera returned a matching response.

        """
        seq = self.next_sequence()
        packet = struct.pack("<IHIH", MAGIC, seq, CMD_CHECK_ONLINE, 0)
        response = self.sync_transaction(
            packet,
            CAMERA_CONTROL_PORT,
            seq,
            timeout=0.12,
            retries=3 if quiet else 6,
            label="CHECK_ONLINE",
        )
        self.camera_connected = response is not None

        if response is None:
            if not quiet:
                self.logger.warning("CHECK_ONLINE: no response; will still try opening video")
            return False

        if not quiet:
            self.logger.info(f"CHECK_ONLINE: Kamera antwortet ({len(response)} Bytes)")

        # Native cameraCheckOnline expects a 0x80-byte status block after a
        # 12-byte protocol header. Preserve it when available.
        if len(response) >= 12:
            payload_len = struct.unpack_from("<H", response, 10)[0]
            if payload_len == 0x80 and len(response) >= 12 + payload_len:
                self.status_payload = response[12 : 12 + payload_len]
                self.capabilities_byte = self.status_payload[124]
                self.dual_stream = bool(self.capabilities_byte & 0x20)
                if not quiet:
                    self.logger.info(
                        "CHECK_ONLINE: 128-Byte-Status erhalten, "
                        f"cap[124]=0x{self.capabilities_byte:02x}, "
                        f"dual-stream={'ja' if self.dual_stream else 'nein'}, "
                        f"time-sync={'ja' if self.capabilities_byte & 0x10 else 'nein'}"
                    )
        return True

    def ensure_camera_connected(self) -> bool:
        """Verify camera availability before an explicit camera command."""
        if not self.running:
            self.camera_connected = False
            self.logger.warning("Camera command skipped: client is not running")
            return False
        self.camera_connected = self.camera_check_online(quiet=True)
        if not self.camera_connected:
            self.logger.warning("Camera command skipped: camera is not connected")
            return False
        return self.camera_connected

    # ------------------------------------------------------------------
    # LED / illumination
    # ------------------------------------------------------------------

    def get_led_status(self, op_type: int = 1) -> tuple[int, int] | None:
        """Read LED status using the exact APK LedStatusGet transport.

        Request:
          cmd 0x0001000A
          payload length 3
          payload: [opType, 0, 0]

        The native wrapper returns payload byte1 as ledStatus and byte2 as
        lightValue.

        Parameters
        ----------
        op_type : int, optional
            Four-bit operation selector sent in the request payload.

        Returns
        -------
        tuple[int, int] | None
            LED state and brightness, or ``None`` if the response is invalid.

        """
        if not self.ensure_camera_connected():
            return None

        seq = self.next_sequence()
        payload = bytes([op_type & 0x0F, 0x00, 0x00])
        packet = (
            struct.pack(
                "<IHIH",
                MAGIC,
                seq,
                CMD_LED_STATUS_GET,
                len(payload),
            )
            + payload
        )

        self.logger.info(f"LED_GET: seq={seq} opType={op_type}")
        self.logger.debug(f"  TX: {packet.hex(' ')}")

        response = self.sync_transaction(
            packet,
            CAMERA_CONTROL_PORT,
            seq,
            timeout=0.25,
            retries=5,
            label="LED_GET",
        )
        if response is None or len(response) < 15:
            self.logger.warning("LED_GET: no or short response")
            return None

        magic, rseq = struct.unpack_from("<IH", response, 0)
        cmd_low = struct.unpack_from("<H", response, 6)[0]
        if magic != MAGIC or rseq != seq or cmd_low != (CMD_LED_STATUS_GET & 0xFFFF):
            self.logger.warning(f"LED_GET: unexpected response header: {response.hex(' ')}")
            return None

        # Native parser checks byte 9 as firmware result for these generic
        # camera commands.
        fw_result = response[9]
        if fw_result != 0:
            self.logger.warning(f"LED_GET: firmware error {fw_result}")
            return None

        payload_len = struct.unpack_from("<H", response, 10)[0]
        if payload_len < 3 or len(response) < 12 + payload_len:
            self.logger.warning(f"LED_GET: invalid payload length {payload_len}: {response.hex(' ')}")
            return None

        rp = response[12 : 12 + payload_len]
        self.led_status = rp[1]
        self.led_value = rp[2]
        self.logger.info(f"LED_GET: status={self.led_status}, value={self.led_value}")
        return self.led_status, self.led_value

    def discover_led_op_type(self) -> int | None:
        """Probe the 4-bit LED operation type with read-only GET requests.

        The native transport masks opType to four bits. Firmware result code 3
        means "unsupported/invalid operation type" on this device.  We try
        0..15 and keep the first GET that succeeds.

        Returns
        -------
        int | None
            First readable operation type, or ``None`` if none responds.

        """
        if self.led_op_type is not None:
            return self.led_op_type

        self.logger.debug("LED_PROBE: test opType 0..15 via GET")
        for op_type in range(16):
            result = self.get_led_status(op_type=op_type)
            if result is not None:
                self.logger.debug(
                    f"LED_PROBE: GET opType={op_type} lesbar "
                    f"(status={result[0]}, value={result[1]}); "
                    "das beweist noch keinen schreibbaren SET-Typ"
                )
                # Keep historical candidate 0 for diagnostic SET attempts,
                # but don't call it successfully discovered.
                self.led_op_type = op_type
                return op_type

        self.logger.debug("LED_PROBE: no opType 0..15 accepted")
        return None

    def set_led(self, enabled: bool) -> bool:
        """Switch the scope illumination using the confirmed YPC payload.

        Parameters
        ----------
        enabled : bool
            Whether to turn the camera LED on.

        Returns
        -------
        bool
            Whether the camera acknowledged the command.

        """
        if not self.ensure_camera_connected():
            return False

        # Confirmed on the tested camera: opType=1, state 0/1 and
        # brightness/value 0/100 over command 0x0001000A.
        op_type = 1

        led_status = 1 if enabled else 0
        light_value = 100 if enabled else 0

        seq = self.next_sequence()
        # Native ARM64 LedStatusSet builds exactly THREE bytes:
        #   byte0 = 0x10 | opType
        #   byte1 = ledStatus
        #   byte2 = lightValue
        # and then reuses the LedStatusGet wire helper.
        payload = bytes([
            0x10 | (op_type & 0x0F),
            led_status,
            light_value,
        ])
        packet = (
            struct.pack(
                "<IHIH",
                MAGIC,
                seq,
                CMD_LED_STATUS_SET,
                len(payload),
            )
            + payload
        )

        label = "LED_ON" if enabled else "LED_OFF"
        self.logger.info(
            f"{label}: seq={seq} opType={op_type} "
            f"ledStatus={led_status} value={light_value} "
            f"(3-Byte native payload via cmd 0x0001000A)"
        )
        self.logger.debug(f"  TX: {packet.hex(' ')}")

        response = self.sync_transaction(
            packet,
            CAMERA_CONTROL_PORT,
            seq,
            timeout=0.25,
            retries=5,
            label=label,
        )
        if response is None or len(response) < 10:
            self.logger.warning(f"{label}: no valid response")
            return False

        magic, rseq = struct.unpack_from("<IH", response, 0)
        cmd_low = struct.unpack_from("<H", response, 6)[0]
        if magic != MAGIC or rseq != seq or cmd_low != (CMD_LED_STATUS_SET & 0xFFFF):
            self.logger.warning(f"{label}: unexpected response header: {response.hex(' ')}")
            return False

        fw_result = response[9]
        if fw_result != 0:
            self.logger.warning(f"{label}: firmware error {fw_result}; response={response.hex(' ')}")
            return False

        self.led_status = led_status
        self.led_value = light_value
        self.logger.info(f"{label}: bestätigt")
        return True

    # ------------------------------------------------------------------
    # Export image transformation
    # ------------------------------------------------------------------

    def _transform_jpeg_for_export(self, jpeg: bytes, camera_angle: float | None) -> bytes:
        """Return the preview-style rotated/circular JPEG for file export.

        The angle belongs to the same completed camera frame as *jpeg*.
        JPEG has no alpha channel, therefore pixels outside the circular
        viewport are rendered black.

        Parameters
        ----------
        jpeg : bytes
            Encoded source frame.
        camera_angle : float | None
            Counter-rotation angle in degrees, or ``None`` to leave the frame unchanged.

        Returns
        -------
        bytes
            Original or transformed JPEG data.
        """
        if camera_angle is None:
            return jpeg

        image = QImage.fromData(jpeg, format="JPEG")  # ty: ignore[invalid-argument-type]
        if image.isNull():
            self.logger.error("EXPORT_ROTATE: JPEG decode failed")
            return jpeg

        side = min(image.width(), image.height())
        output = QImage(side, side, QImage.Format.Format_RGB32)
        output.fill(Qt.GlobalColor.black)

        painter = QPainter(output)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, True)

        clip = QPainterPath()
        clip.addEllipse(QRectF(0.0, 0.0, float(side), float(side)))
        painter.setClipPath(clip)
        painter.translate(side / 2.0, side / 2.0)
        painter.rotate(-float(camera_angle))
        painter.drawImage(
            int(-image.width() / 2),
            int(-image.height() / 2),
            image,
        )
        painter.end()

        encoded = QByteArray()
        buffer = QBuffer(encoded)
        if not buffer.open(QIODevice.OpenModeFlag.WriteOnly):
            self.logger.error("EXPORT_ROTATE: could not open QBuffer")
            return jpeg
        ok = output.save(buffer, b"JPEG", 95)
        buffer.close()
        if not ok:
            self.logger.error("EXPORT_ROTATE: JPEG encoding failed")
            return jpeg
        return bytes(encoded.data())

    # ------------------------------------------------------------------
    # Camera recording state (native proRecordStatusSync)
    # ------------------------------------------------------------------

    def camera_record_status_sync(self, recording: bool) -> bool:
        """Try the optional camera-side recording-status sync command.

        The tested YPC camera rejects this optional status-sync feature with
        result code 2. Local recording does not depend on it.

        Parameters
        ----------
        recording : bool
            True when announcing recording start, false for stop.

        Returns
        -------
        bool
            Whether the camera acknowledged the status command.

        """
        if not self.ensure_camera_connected():
            self.record_remote_error = "offline"
            return False

        status = 1 if recording else 0
        seq = self.next_sequence()
        packet = struct.pack(
            "<IHIHB",
            MAGIC,
            seq,
            CMD_RECORD_STATUS_SYNC,
            1,
            status,
        )

        label = "RECORD_SYNC_START" if recording else "RECORD_SYNC_STOP"
        self.logger.info(f"{label}: seq={seq} status={status} -> {self.camera_ip}:{CAMERA_CONTROL_PORT}")
        self.logger.debug(f"  TX: {packet.hex(' ')}")

        response = self.sync_transaction(
            packet,
            CAMERA_CONTROL_PORT,
            seq,
            timeout=0.25,
            retries=5,
            label=label,
        )
        if response is None or len(response) < 10:
            self.logger.warning(f"{label}: no valid response")
            self.record_remote_error = "timeout"
            return False

        magic, rseq = struct.unpack_from("<IH", response, 0)
        cmd_low = struct.unpack_from("<H", response, 6)[0]
        expected_low = CMD_RECORD_STATUS_SYNC & 0xFFFF
        firmware_result = response[9]
        echoed_status = response[12] if len(response) >= 13 else None

        if magic != MAGIC or rseq != seq or cmd_low != expected_low:
            self.logger.warning(
                f"{label}: unexpected response header magic=0x{magic:08x} seq={rseq} cmd_low=0x{cmd_low:04x}"
            )
            self.record_remote_error = "bad-header"
            return False

        if firmware_result != 0:
            self.logger.warning(
                f"{label}: Firmware lehnt optionalen RecordStatusSync ab (code={firmware_result}, echoed_status={echoed_status}). Local recording can continue."
            )
            self.record_remote_error = firmware_result
            return False

        self.logger.info(f"{label}: ACK bestätigt (echoed_status={echoed_status})")
        self.record_remote_error = None
        return True

    def _record_filename(self) -> str:
        """Create an absolute timestamped Matroska output path.

        Returns
        -------
        str
            Path for the next local recording.
        """
        stamp = time.strftime("%Y%m%d-%H%M%S")
        return os.path.abspath(f"soulear-recording-{stamp}.mkv")

    def start_video_recording(self) -> bool:
        """Start local MJPEG recording and notify the camera when possible.

        Returns
        -------
        bool
            Whether recording state was started; true can indicate camera-only
            recording state when ffmpeg is unavailable.

        Raises
        ------
        OSError
            If camera status synchronization cannot use its UDP socket.
        """
        with self.record_lock:
            if self.camera_recording:
                self.logger.info("RECORD_START: Aufnahme läuft bereits")
                return False

            # Freeze export orientation mode for the whole recording.
            # The GUI also locks the toggle while recording.
            self.record_auto_rotate = bool(self.auto_rotate)

            # Optional firmware status sync.  Some related models support it;
            # this Soulear firmware currently answers with result code 2.
            self.record_remote_active = self.camera_record_status_sync(True)

            output = self._record_filename()
            ffmpeg = shutil.which("ffmpeg")
            if ffmpeg is None:
                self.camera_recording = True
                self.record_output_path = None
                self.record_start_resolution = self.last_jpeg_resolution
                self.record_seen_resolutions = set()
                self.record_frame_count = 0
                self.logger.warning("RECORD_START: ffmpeg not found; local video file will not be created")
                return True

            cmd = [
                ffmpeg,
                "-hide_banner",
                "-loglevel",
                "error",
                "-y",
                "-f",
                "image2pipe",
                "-framerate",
                str(self.record_fps),
                "-vcodec",
                "mjpeg",
                "-i",
                "pipe:0",
                "-an",
            ]
            # Input is MJPEG in both modes. Auto-rotation re-encodes each
            # source frame once in _transform_jpeg_for_export(); ffmpeg only
            # muxes those JPEG frames into Matroska without another encode.
            cmd += ["-c:v", "copy", output]

            try:
                proc = subprocess.Popen(  # noqa: S603
                    cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    bufsize=0,
                )
            except Exception:
                self.logger.exception("RECORD_START: could not start ffmpeg")
                self.camera_record_status_sync(False)
                return False

            self.record_ffmpeg = proc
            self.record_output_path = output
            self.camera_recording = True
            self.record_start_resolution = self.last_jpeg_resolution
            self.record_seen_resolutions = set()
            self.record_frame_count = 0

            self.logger.info(
                f"RECORD_START: lokale Datei {output}; "
                f"Start-Preview={self.record_start_resolution}; "
                f"auto_rotate={'ja' if self.record_auto_rotate else 'nein'}; "
                f"remote_sync={'aktiv' if self.record_remote_active else 'nicht unterstützt'}"
            )
            return True

    def stop_video_recording(self) -> bool:
        """Stop local recording and synchronize camera recording state.

        Returns
        -------
        bool
            Whether the camera acknowledged the stop request.

        Raises
        ------
        OSError
            If camera status synchronization cannot use its UDP socket.
        """
        with self.record_lock:
            if not self.camera_recording and self.record_ffmpeg is None:
                self.logger.debug("RECORD_STOP: no recording is active")
                return False

            if self.record_remote_active:
                remote_ok = self.camera_record_status_sync(False)
            else:
                remote_ok = False
                self.logger.debug(
                    "RECORD_SYNC_STOP: übersprungen, weil Firmware den RecordStatusSync beim Start nicht unterstützt hat."
                )

            proc = self.record_ffmpeg
            output = self.record_output_path
            self.record_ffmpeg = None
            self.camera_recording = False
            remote_was_active = self.record_remote_active
            self.record_remote_active = False
            record_auto_rotate = self.record_auto_rotate
            self.record_auto_rotate = False

            if proc is not None:
                try:
                    if proc.stdin:
                        proc.stdin.close()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.terminate()
                        proc.wait(timeout=2)
                except Exception:
                    self.logger.exception("RECORD_STOP: ffmpeg shutdown failed")

                if proc.returncode not in (0, None):
                    try:
                        err = "" if proc.stderr is None else proc.stderr.read().decode("utf-8", "replace").strip()
                    except Exception:
                        err = ""
                    if err:
                        self.logger.error(f"RECORD_STOP: ffmpeg: {err}")

            self.logger.info(
                f"RECORD_STOP: frames={self.record_frame_count}, "
                f"Start={self.record_start_resolution}, "
                f"gesehen={sorted(self.record_seen_resolutions)}, "
                f"Datei={output or '-'}, "
                f"auto_rotate={'ja' if record_auto_rotate else 'nein'}, "
                f"remote_sync={'ja' if remote_was_active else 'unsupported'}, "
                f"remote_stop_ack={'ja' if remote_ok else 'nein'}"
            )
            return remote_ok

    def _record_jpeg(self, jpeg: bytes, width: int, height: int, camera_angle: float | None = None) -> None:
        """Write a complete frame to the active ffmpeg input pipe.

        Parameters
        ----------
        jpeg : bytes
            Encoded frame data.
        width : int
            Actual JPEG width in pixels.
        height : int
            Actual JPEG height in pixels.
        camera_angle : float | None, optional
            Per-frame rotation angle used when recording with auto-rotation.
        """
        with self.record_lock:
            if not self.camera_recording:
                return

            current = (int(width), int(height))
            self.record_seen_resolutions.add(current)
            self.record_frame_count += 1

            if self.record_start_resolution and current != self.record_start_resolution:
                self.logger.info(f"RECORDING RESOLUTION CHANGE: {self.record_start_resolution} -> {width}x{height}")
                self.record_start_resolution = current

            proc = self.record_ffmpeg
            if proc is None or proc.stdin is None:
                return

            export_jpeg = self._transform_jpeg_for_export(jpeg, camera_angle) if self.record_auto_rotate else jpeg

            try:
                proc.stdin.write(export_jpeg)
            except (BrokenPipeError, OSError):
                self.logger.exception("RECORD: ffmpeg pipe failed")
                with suppress(Exception):
                    proc.stdin.close()
                self.record_ffmpeg = None

    # ------------------------------------------------------------------
    # Camera time
    # ------------------------------------------------------------------

    def set_camera_time(self) -> bool:
        """Set the camera clock to the local system time.

        Returns
        -------
        bool
            Whether the camera acknowledged the time command.

        """
        if not self.ensure_camera_connected():
            return False

        now = time.localtime()
        seq = self.next_sequence()
        packet = struct.pack(
            "<IHIHHBBBBB",
            MAGIC,
            seq,
            CMD_SET_TIME,
            7,
            now.tm_year,
            now.tm_mon,
            now.tm_mday,
            now.tm_hour,
            now.tm_min,
            now.tm_sec,
        )
        response = self.sync_transaction(
            packet,
            CAMERA_CONTROL_PORT,
            seq,
            timeout=0.5,
            retries=2,
            label="SET_TIME",
        )
        if response is not None:
            self.logger.info("SET_TIME: bestätigt")
            return True
        self.logger.warning("SET_TIME: no acknowledgement")
        return False

    # ------------------------------------------------------------------
    # Normal proOpenVideo (0x00010004 -> UDP 10006)
    # ------------------------------------------------------------------

    def open_video_normal(self, reason: str = "initial") -> bool:
        """Request the normal camera video stream.

        Parameters
        ----------
        reason : str, optional
            Diagnostic label describing why the stream is being opened.

        Returns
        -------
        bool
            Whether the camera acknowledged the open request.

        """
        seq = self.next_sequence()

        # proOpenVideo uses subtype 2 with the primary dynamic receiver.
        # When status capability bit 5 is set, it uses subtype 4 and also
        # includes the second dynamic receiver. For 192.168.1.255 the native
        # function sends the 16-byte form.
        subtype = 4 if self.dual_stream else 2
        secondary = self.video2_port if self.dual_stream else 0

        packet = struct.pack(
            "<IHIHHH",
            MAGIC,
            seq,
            CMD_OPEN_VIDEO,
            subtype,
            self.video_port,
            secondary,
        )

        self.logger.debug(
            f"OPEN_VIDEO(normal/{reason}): seq={seq} subtype={subtype} primary={self.video_port} secondary={secondary}"
        )
        self.logger.debug(f"  TX: {packet.hex(' ')}")

        response = self.sync_transaction(
            packet,
            CAMERA_VIDEO_COMMAND_PORT,
            seq,
            timeout=0.12,
            retries=5,
            label="OPEN_VIDEO",
        )
        self.last_open_time = time.monotonic()
        self.normal_open_acked = response is not None

        if response is not None:
            self.logger.info(f"OPEN_VIDEO(normal): ACK ({len(response)} Bytes)")
            self.signals.status.emit("Normaler Videostream geöffnet")
            return True

        self.logger.warning("OPEN_VIDEO(normal): no acknowledgement")
        return False

    # ------------------------------------------------------------------
    # Experimental native proOpenVideo variants
    # ------------------------------------------------------------------

    def open_video_force(self, reason: str = "fallback") -> bool:
        """Request the experimental force-open camera video path.

        Parameters
        ----------
        reason : str, optional
            Diagnostic label describing why the fallback is being tried.

        Returns
        -------
        bool
            Whether the camera acknowledged the open request.

        """
        seq = self.next_sequence()
        packet = struct.pack(
            "<IHIHH",
            MAGIC,
            seq,
            CMD_OPEN_VIDEO_FORCE,
            0,
            self.video_port,
        )
        self.logger.debug(f"OPEN_VIDEO_FORCE({reason}): seq={seq} video_port={self.video_port}")
        self.logger.debug(f"  TX: {packet.hex(' ')}")
        response = self.sync_transaction(
            packet,
            CAMERA_VIDEO_COMMAND_PORT,
            seq,
            timeout=0.12,
            retries=5,
            label="OPEN_VIDEO_FORCE",
        )
        self.force_open_used = True
        self.last_open_time = time.monotonic()
        if response is not None:
            self.logger.info(f"OPEN_VIDEO_FORCE: ACK ({len(response)} Bytes)")
            self.signals.status.emit("Force-Videopfad geöffnet")
            return True
        self.logger.warning("OPEN_VIDEO_FORCE: no acknowledgement")
        return False

    def send_ne7_probe(self) -> None:
        """One-shot discovery/legacy-stream probe based on haxko/NE3-Scope.

        Related NE7 firmware sends 66 39 01 01 to broadcast ports 58090 and
        46526, then 86 06 01 to 52219 and 20 36 to 44506.
        Our native Soulear library uses a close variant (66 30 01 01), so this
        is sent only once as a compatibility probe.
        """
        if not self.keepalives_enabled:
            return
        control2_socket = self.presence_control2_socket
        control1_socket = self.presence_control1_socket
        video_socket = self.presence_video_socket
        if control2_socket is None or control1_socket is None or video_socket is None:
            return
        try:
            probe = bytes([0x66, 0x39, 0x01, 0x01])
            control2_socket.sendto(probe, (self.broadcast_ip, 58090))
            control2_socket.sendto(probe, (self.broadcast_ip, 46526))
            control1_socket.sendto(
                KEEPALIVE_CONTROL1,
                (self.camera_ip, PRESENCE_CONTROL1_PORT),
            )
            video_socket.sendto(
                KEEPALIVE_VIDEO,
                (self.camera_ip, PRESENCE_VIDEO_PORT),
            )
            self.logger.debug("NE7 probe: 66 39 01 01 -> :58090/:46526; 86 06 01 -> :52219; 20 36 -> :44506")
        except OSError as exc:
            self.logger.warning(f"NE7 probe failed: {exc}")

    def keepalive_loop(self) -> None:
        """Send periodic camera-presence datagrams while the client is running."""
        control2_socket = self.presence_control2_socket
        control1_socket = self.presence_control1_socket
        video_socket = self.presence_video_socket
        if control2_socket is None or control1_socket is None or video_socket is None:
            return
        start = time.monotonic()
        next_control = start + 4.0
        next_video = start + 6.0

        while self.running:
            now = time.monotonic()
            if now >= next_control:
                try:
                    control2_socket.sendto(
                        KEEPALIVE_CONTROL2,
                        (self.broadcast_ip, PRESENCE_CONTROL2_DEST),
                    )
                    control1_socket.sendto(
                        KEEPALIVE_CONTROL1,
                        (self.broadcast_ip, PRESENCE_CONTROL1_PORT),
                    )
                    self.logger.debug("PRESENCE: 66 30 01 01 -> :46526; 86 06 01 -> :52219")
                except OSError as exc:
                    self.logger.warning(f"PRESENCE control send failed: {exc}")
                    return
                next_control = now + 1.0

            if now >= next_video:
                try:
                    video_socket.sendto(
                        KEEPALIVE_VIDEO,
                        (self.broadcast_ip, PRESENCE_VIDEO_PORT),
                    )
                    self.logger.debug("PRESENCE: 20 36 -> :44506")
                except OSError as exc:
                    self.logger.warning(f"PRESENCE video send failed: {exc}")
                    return
                next_video = now + 3.0

            time.sleep(0.02)

    # ------------------------------------------------------------------
    # Periodic online check (the native info thread does this repeatedly)
    # ------------------------------------------------------------------

    def online_monitor_loop(self) -> None:
        """Check camera availability periodically until the client stops."""
        # Do not collide with initial setup.
        time.sleep(2.0)
        while self.running:
            try:
                ok = self.camera_check_online(quiet=True)
                self.logger.debug(f"ONLINE monitor: {'ok' if ok else 'no response'}")
            except Exception as exc:
                self.logger.warning(f"ONLINE monitor failed: {exc}")
            for _ in range(30):
                if not self.running:
                    return
                time.sleep(0.1)

    # ------------------------------------------------------------------
    # Optional dumpcap diagnostic capture
    # ------------------------------------------------------------------

    def detect_interface(self) -> str:
        """Return the configured interface or detect the camera route.

        Returns
        -------
        str
            Interface name used for packet capture.

        Raises
        ------
        CaptureError
            If ``ip`` is unavailable or no interface can be determined.
        """
        if self.interface:
            return self.interface
        ip_command = shutil.which("ip")
        if ip_command is None:
            raise CaptureError("ip")
        try:
            result = subprocess.run(  # noqa: S603
                [ip_command, "route", "get", self.camera_ip],
                check=True,
                capture_output=True,
                text=True,
                timeout=2,
            )
            match = re.search(r"\bdev\s+(\S+)", result.stdout)
            if match:
                self.interface = match.group(1)
                return self.interface
        except (OSError, subprocess.SubprocessError) as exc:
            self.logger.debug(f"Interface detection failed: {exc}")
        raise CaptureError("interface")

    def start_dumpcap(self) -> None:
        """Start dumpcap and a background thread to drain its stderr.

        Raises
        ------
        CaptureError
            If dumpcap is unavailable or the network interface is unknown.
        OSError
            If the dumpcap process cannot be started.
        """
        dumpcap = shutil.which("dumpcap")
        if dumpcap is None:
            raise CaptureError("dumpcap")
        interface = self.detect_interface()

        command = [
            dumpcap,
            "-q",
            "-F",
            "pcap",
            "-i",
            interface,
            "-s",
            "0",
            "-w",
            "-",
        ]
        self.logger.debug("%s %s", "Capture:", " ".join(command))
        self.dumpcap_process = subprocess.Popen(  # noqa: S603
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        threading.Thread(
            target=self.dumpcap_stderr_loop,
            daemon=True,
        ).start()

    def dumpcap_stderr_loop(self) -> None:
        """Read dumpcap diagnostics and print them when debug mode is enabled."""
        process = self.dumpcap_process
        if process is None or process.stderr is None:
            return
        for raw_line in process.stderr:
            line = raw_line.decode(errors="replace").strip()
            if line and self.debug:
                self.logger.debug(f"[dumpcap] {line}")

    def capture_loop(self) -> None:
        """Run optional dumpcap capture and dispatch Ethernet frames."""
        try:
            self.start_dumpcap()
            reader = self._dumpcap_reader()
            self.logger.info(f"Optional dumpcap capture active on {self.interface}")
            for ethernet_frame in reader.packets():
                if not self.running:
                    break
                self.process_ethernet_frame(ethernet_frame)
        except Exception as exc:
            if self.running:
                self.logger.exception("CAPTURE ERROR")
                self.signals.status.emit(f"Capture-Fehler: {exc}")

    def _dumpcap_reader(self) -> PcapStreamReader:
        """Create a PCAP reader for the running dumpcap process.

        Returns
        -------
        PcapStreamReader
            Reader connected to dumpcap's standard output.

        Raises
        ------
        CaptureError
            If the process or its output stream is unavailable.
        """
        process = self.dumpcap_process
        if process is None or process.stdout is None:
            raise CaptureError("stdout")
        return PcapStreamReader(process.stdout)

    # ------------------------------------------------------------------
    # Ethernet / IPv4 / UDP parser
    # ------------------------------------------------------------------

    def decode_gyro_52219(self, src_port: int, dst_port: int, payload: bytes) -> bool:
        """Decode the related NE7/Soulear gyro packet on UDP 52219.

        NE3-Scope/client2.py uses:
            struct.unpack(">BxBxBxxxxxxxxxxxxxHxxxx", data)

        The resulting values are x, y, z and a big-endian angle in degrees.

        Parameters
        ----------
        src_port : int
            Packet source UDP port.
        dst_port : int
            Packet destination UDP port; retained for a uniform decoder interface.
        payload : bytes
            UDP payload to inspect.

        Returns
        -------
        bool
            True when the packet is recognized as a gyro packet.
        """
        if src_port != PRESENCE_CONTROL1_PORT:
            return False
        if len(payload) < 25:
            return False

        try:
            x, y, z, angle = struct.unpack(
                ">BxBxBxxxxxxxxxxxxxHxxxx",
                payload[:25],
            )
        except struct.error:
            return False

        self.gyro_packet_count += 1
        self.gyro_xyz = (x, y, z)

        if 0 <= angle <= 359:
            old = self.last_camera_angle
            # Keep the Soulear per-frame angle as primary. 52219 is only
            # diagnostic/compatibility data if this firmware ever sends it.
            if old is None:
                self.last_camera_angle = angle
            if self.debug and (old is None or abs(angle - old) >= 2 or self.gyro_packet_count <= 5):
                self.logger.debug(
                    f"GYRO52219 #{self.gyro_packet_count}: x={x} y={y} z={z} angle={angle}° raw={payload[:25].hex(' ')}"
                )
        else:
            self.logger.debug(
                f"GYRO52219 #{self.gyro_packet_count}: angle={angle} außerhalb 0..359, raw={payload[:25].hex(' ')}"
            )

        return True

    def decode_notify_packet(self, src_port: int, dst_port: int, payload: bytes) -> bool:
        """Decode the observed UDP/10007 command-9 notify envelope.

        Type 2 contains status/bit fields. It does not carry width/height and
        is not used as a resolution/open-video command by this client.

        Parameters
        ----------
        src_port : int
            Packet source UDP port; retained for a uniform decoder interface.
        dst_port : int
            Packet destination UDP port; retained for a uniform decoder interface.
        payload : bytes
            Candidate command notification payload.

        Returns
        -------
        bool
            True when the packet is a recognized notify envelope.
        """
        if len(payload) < 13:
            return False

        magic = struct.unpack_from("<I", payload, 0)[0]
        if magic != MAGIC:
            return False

        command = struct.unpack_from("<I", payload, 6)[0]
        if command != 0x00000009:
            return False

        declared_len = struct.unpack_from("<H", payload, 10)[0]
        body = payload[12 : 12 + declared_len]
        if not body:
            return True

        self.notify_packet_count += 1
        notify_type = body[0]

        if notify_type == 2 and len(body) >= 5:
            # These bit extractions are taken directly from the native parser.
            status_word = struct.unpack_from("<H", body, 1)[0]
            bit0 = status_word & 0x1
            bits1_7 = (status_word >> 1) & 0x7F
            bit8 = (status_word >> 8) & 0x1
            bits9_15 = (status_word >> 9) & 0x7F
            field3 = body[3]
            field4 = struct.unpack_from("<b", body, 4)[0]

            extra = ""
            if len(body) >= 17:
                word9 = struct.unpack_from("<H", body, 9)[0]
                byte11 = body[11]
                byte16 = body[16]
                extra = f" ext9=0x{word9:04x} ext11=0x{byte11:02x} ext16=0x{byte16:02x}"

            self.logger.debug(
                f"NOTIFY #{self.notify_packet_count} cmd=0x00000009 "
                f"type=2 len={declared_len} "
                f"status=0x{status_word:04x} "
                f"b0={bit0} bits1_7={bits1_7} b8={bit8} "
                f"bits9_15={bits9_15} field3={field3} field4={field4}"
                f"{extra}"
            )
        else:
            self.logger.debug(
                f"NOTIFY #{self.notify_packet_count} cmd=0x00000009 "
                f"type={notify_type} len={declared_len} "
                f"body={body[:32].hex(' ')}"
            )

        return True

    @staticmethod
    def jpeg_dimensions(jpeg: bytes) -> tuple[int, int]:
        """Read image dimensions from the first supported JPEG SOF marker.

        Parameters
        ----------
        jpeg : bytes
            Encoded JPEG data.

        Returns
        -------
        tuple[int, int]
            Width and height in pixels, or ``(0, 0)`` when no valid SOF marker exists.
        """
        try:
            i = 2
            n = len(jpeg)
            while i + 9 < n:
                if jpeg[i] != 0xFF:
                    i += 1
                    continue
                while i < n and jpeg[i] == 0xFF:
                    i += 1
                if i >= n:
                    break
                marker = jpeg[i]
                i += 1
                if marker in (0xD8, 0xD9):
                    continue
                if i + 2 > n:
                    break
                seglen = int.from_bytes(jpeg[i : i + 2], "big")
                if seglen < 2 or i + seglen > n:
                    break
                if (
                    marker
                    in (
                        0xC0,
                        0xC1,
                        0xC2,
                        0xC3,
                        0xC5,
                        0xC6,
                        0xC7,
                        0xC9,
                        0xCA,
                        0xCB,
                        0xCD,
                        0xCE,
                        0xCF,
                    )
                    and seglen >= 7
                ):
                    h = int.from_bytes(jpeg[i + 3 : i + 5], "big")
                    w = int.from_bytes(jpeg[i + 5 : i + 7], "big")
                    return w, h
                i += seglen
        except (IndexError, ValueError):
            pass
        return 0, 0

    def reset_legacy_frame(self, frame_number: int | None = None) -> None:
        """Clear the legacy chunk buffer and select an optional active frame.

        Parameters
        ----------
        frame_number : int | None, optional
            Frame identifier to begin tracking, or ``None`` to clear it.
        """
        self.legacy_frame_number = frame_number
        self.legacy_chunks = {}
        self.legacy_last_chunk = None

    def process_legacy_44506_packet(self, payload: bytes) -> None:
        """NE7-Scope compatible legacy transport.

        Header:
          byte0 frame_number
          byte1 flags (bit0 = final packet)
          byte2 chunk_number (1-based)
          byte3 flags2
        The final packet carries a 5-byte trailer after JPEG data.

        Parameters
        ----------
        payload : bytes
            One legacy UDP payload containing a frame/chunk header and image data.
        """
        if len(payload) < 5:
            return

        frame_number, flags, chunk_number, flags2 = payload[:4]
        if chunk_number == 0:
            return

        data = payload[4:]
        is_last = bool(flags & 0x01)
        if is_last:
            if len(data) < 5:
                return
            data = data[:-5]

        self.legacy_packet_count += 1

        if self.legacy_frame_number is None:
            self.reset_legacy_frame(frame_number)
        elif frame_number != self.legacy_frame_number:
            # New frame started before the old one completed.
            if self.legacy_chunks:
                self.logger.debug(
                    f"LEGACY44506: frame jump {self.legacy_frame_number}->{frame_number}; old frame dropped"
                )
            self.reset_legacy_frame(frame_number)

        self.legacy_chunks[chunk_number - 1] = data

        if self.debug and (chunk_number == 1 or is_last):
            self.logger.debug(
                f"LEGACY44506 pkt#{self.legacy_packet_count}: "
                f"frame={frame_number} chunk={chunk_number} "
                f"flags=0x{flags:02x} flags2=0x{flags2:02x} "
                f"last={'yes' if is_last else 'no'} len={len(payload)}"
            )

        if not is_last:
            return

        self.legacy_last_chunk = chunk_number
        self._finish_legacy_frame(frame_number, chunk_number)

    def _finish_legacy_frame(self, frame_number: int, chunk_number: int) -> None:
        """Validate, join, and publish the completed legacy JPEG frame.

        Parameters
        ----------
        frame_number : int
            Legacy frame identifier used in diagnostics and the emitted frame ID.
        chunk_number : int
            One-based index of the final expected chunk.
        """
        expected = set(range(chunk_number))
        present = set(self.legacy_chunks.keys())
        missing = sorted(expected - present)
        if missing:
            self.logger.warning(
                f"LEGACY44506: frame {frame_number} incomplete; missing chunks={[x + 1 for x in missing]}"
            )
            self.reset_legacy_frame()
            return

        jpeg = b"".join(self.legacy_chunks[i] for i in range(chunk_number))
        self.reset_legacy_frame()

        soi = jpeg.find(JPEG_SOI)
        if soi > 0:
            jpeg = jpeg[soi:]
        eoi = jpeg.rfind(JPEG_EOI)
        if eoi >= 0:
            jpeg = jpeg[: eoi + 2]

        if not jpeg.startswith(JPEG_SOI) or not jpeg.endswith(JPEG_EOI):
            self.logger.warning(f"LEGACY44506: frame {frame_number} is not a complete JPEG ({len(jpeg)} bytes)")
            return

        width, height = self.jpeg_dimensions(jpeg)
        self.legacy_frame_count += 1
        self.logger.debug(
            f"LEGACY44506 JPEG #{self.legacy_frame_count}: "
            f"frame={frame_number} {len(jpeg):,} Bytes "
            f"{width if width else '?'}x{height if height else '?'}"
        )

        # Feed the same GUI/output path as the modern stream.
        self.emit_jpeg(
            jpeg,
            f"L{frame_number}",
            width,
            height,
        )

    def process_ethernet_frame(self, frame: bytes) -> None:
        """Parse an Ethernet frame and dispatch its camera UDP payload.

        Parameters
        ----------
        frame : bytes
            Ethernet frame containing an IPv4/UDP datagram.
        """
        packet = self._extract_udp_packet(frame)
        if packet is None:
            return

        src_ip, dst_ip, src_port, dst_port, payload = packet
        self.raw_packet_count += 1

        if self.decode_gyro_52219(src_port, dst_port, payload):
            return
        if self._handle_control_packet(src_ip, dst_ip, src_port, dst_port, payload):
            return
        if src_port == PRESENCE_VIDEO_PORT and dst_port == PRESENCE_VIDEO_PORT:
            self.process_legacy_44506_packet(payload)
            return
        self._process_video_transport_packet(src_ip, dst_ip, src_port, dst_port, payload)

    def _extract_udp_packet(self, frame: bytes) -> tuple[str, str, int, int, bytes] | None:
        """Validate Ethernet/IPv4/UDP headers and extract a camera datagram.

        Parameters
        ----------
        frame : bytes
            Candidate Ethernet frame.

        Returns
        -------
        tuple[str, str, int, int, bytes] | None
            Source IP, destination IP, source port, destination port, and payload;
            ``None`` when the frame is malformed or is not from this camera.
        """
        if len(frame) < 14 + 20 + 8:
            return None
        if frame[12:14] != b"\x08\x00":
            return None

        ip_offset = 14
        version_ihl = frame[ip_offset]
        if version_ihl >> 4 != 4:
            return None
        ihl = (version_ihl & 0x0F) * 4
        if ihl < 20 or len(frame) < ip_offset + ihl + 8:
            return None
        if frame[ip_offset + 9] != 17:
            return None

        src_ip = socket.inet_ntoa(frame[ip_offset + 12 : ip_offset + 16])
        dst_ip = socket.inet_ntoa(frame[ip_offset + 16 : ip_offset + 20])
        if src_ip != self.camera_ip:
            return None

        udp_offset = ip_offset + ihl
        src_port, dst_port, udp_len = struct.unpack_from("!HHH", frame, udp_offset)
        if udp_len < 8:
            return None

        payload_offset = udp_offset + 8
        payload = frame[payload_offset : payload_offset + udp_len - 8]
        if not payload:
            return None
        return src_ip, dst_ip, src_port, dst_port, payload

    def _handle_control_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bool:
        """Decode a notify or control datagram and consume recognized packets.

        Parameters
        ----------
        src_ip : str
            Source IPv4 address for diagnostics.
        dst_ip : str
            Destination IPv4 address for diagnostics.
        src_port : int
            Source UDP port passed to the notify decoder.
        dst_port : int
            Destination UDP port passed to the notify decoder.
        payload : bytes
            Datagram payload to inspect.

        Returns
        -------
        bool
            True when the payload is a control packet and should not be parsed as video.
        """
        if len(payload) >= 4 and payload[:4] == struct.pack("<I", MAGIC):
            if self.decode_notify_packet(src_port, dst_port, payload):
                return True

            self.control_packet_count += 1
            self.logger.debug(
                f"RAW CONTROL #{self.control_packet_count}: "
                f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                f"len={len(payload)} {payload[:24].hex(' ')}"
            )
            return True
        return False

    def _process_video_transport_packet(
        self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes
    ) -> None:
        """Validate a Soulear video datagram and forward current-stream packets.

        Parameters
        ----------
        src_ip : str
            Packet source IPv4 address.
        dst_ip : str
            Packet destination IPv4 address.
        src_port : int
            Packet source UDP port.
        dst_port : int
            Packet destination UDP port.
        payload : bytes
            Video transport header and fragment bytes.
        """
        if len(payload) < VIDEO_HEADER_SIZE:
            if self.debug and self.raw_packet_count <= 5:
                self.logger.debug(f"VIDEO reject: short packet len={len(payload)} from {src_ip}:{src_port}")
            return

        # Validate a Soulear video header rather than relying only on the
        # malformed UDP destination. Native receiver accepts types 1,2,5,6.
        stream_type = payload[0]
        if stream_type not in (1, 2, 5, 6):
            if self.debug and self.raw_packet_count <= 5:
                self.logger.debug(
                    f"VIDEO reject: type=0x{stream_type:02x} from {src_ip}:{src_port} "
                    f"to {dst_ip}:{dst_port} len={len(payload)} hdr={payload[:16].hex(' ')}"
                )
            return

        width = struct.unpack_from("<H", payload, 12)[0]
        height = struct.unpack_from("<H", payload, 14)[0]
        if not (16 <= width <= 4096 and 16 <= height <= 4096):
            if self.debug and self.raw_packet_count <= 5:
                self.logger.debug(
                    f"VIDEO reject: dimensions={width}x{height} from {src_ip}:{src_port} "
                    f"to {dst_ip}:{dst_port} len={len(payload)} hdr={payload[:16].hex(' ')}"
                )
            return

        # Diagnostic capture can see stale streams from earlier sessions too.
        # Only frames addressed to THIS client's current primary/secondary
        # receive ports are allowed into the JPEG/reassembly state machine.
        current_ports = {self.video_port, self.video2_port}
        current_ports.discard(0)
        if dst_port not in current_ports:
            self.stale_video_count += 1
            now = time.monotonic()
            # One summary per second (or immediately when the stale port changes)
            # is enough; previous versions could print thousands of lines.
            if self.debug and (now - self._last_stale_log_time >= 1.0 or dst_port != self._last_stale_port):
                self.logger.debug(
                    f"STALE VIDEO ignored: port={dst_port} {width}x{height}; "
                    f"count={self.stale_video_count}, "
                    f"current ports={sorted(current_ports)}"
                )
                self._last_stale_log_time = now
                self._last_stale_port = dst_port
            return

        self.video_packet_count += 1
        self.last_video_packet_time = time.monotonic()
        self.first_video_event.set()

        if self.debug and (self.video_packet_count <= 10 or self.video_packet_count % self.video_log_every == 0):
            self.logger.debug(
                f"VIDEO #{self.video_packet_count:6d}: "
                f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                f"len={len(payload)} hdr={payload[:16].hex(' ')}"
            )

        self.process_video_packet(payload)

    # ------------------------------------------------------------------
    # Video/JPEG reassembly
    # ------------------------------------------------------------------

    @staticmethod
    def circular_delta_deg(new_angle: float, old_angle: float) -> float:
        """Compute the shortest signed angular difference in ``[-180, 180)``.

        Parameters
        ----------
        new_angle : float
            Current angle in degrees.
        old_angle : float
            Reference angle in degrees.

        Returns
        -------
        float
            Signed shortest rotation from the reference to the current angle.
        """
        return ((new_angle - old_angle + 180.0) % 360.0) - 180.0

    def filter_camera_angle(self, raw_angle: float) -> float:
        """Apply wrap-aware smoothing and reject implausible angle jumps.

        Parameters
        ----------
        raw_angle : float
            Absolute sensor angle in degrees.

        Returns
        -------
        float
            Filtered absolute camera angle in the range ``[0, 360)``.
        """
        raw_angle %= 360.0
        self.raw_camera_angle = raw_angle

        if self.last_camera_angle is None:
            self.last_camera_angle = raw_angle
            return raw_angle

        delta = self.circular_delta_deg(raw_angle, self.last_camera_angle)

        # The raw metadata occasionally flips by roughly 100-180 degrees.
        if abs(delta) > self.angle_reject_jump:
            self.angle_reject_count += 1
            return self.last_camera_angle

        step = delta * self.angle_filter_alpha
        step = max(-self.angle_max_step, min(self.angle_max_step, step))
        self.last_camera_angle = (self.last_camera_angle + step) % 360.0
        return self.last_camera_angle

    def relative_auto_rotate_angle(self, filtered_angle: float | None) -> float | None:
        """Convert an absolute angle to a rotation relative to auto-rotate start.

        Parameters
        ----------
        filtered_angle : float | None
            Filtered absolute angle in degrees.

        Returns
        -------
        float | None
            Relative angle in degrees, or ``None`` before an angle is available.
        """
        if filtered_angle is None:
            return None
        if self.auto_rotate_zero is None:
            self.auto_rotate_zero = filtered_angle
        return self.circular_delta_deg(filtered_angle, self.auto_rotate_zero)

    def process_video_packet(self, payload: bytes) -> None:
        """Decode motion metadata, assemble JPEG fragments, and publish frames.

        Parameters
        ----------
        payload : bytes
            Soulear video datagram containing a 16-byte header and fragment data.
        """
        header = payload[:VIDEO_HEADER_SIZE]
        data = payload[VIDEO_HEADER_SIZE:]
        packet_sequence = header[1]
        frame_id = header[2]
        flags = header[3]
        last_fragment = bool(flags & 0x01)
        camera_angle = self._update_motion_metadata(header)
        width = struct.unpack_from("<H", header, 12)[0]
        height = struct.unpack_from("<H", header, 14)[0]

        completed_frame = self._collect_jpeg_fragment(
            data,
            packet_sequence,
            frame_id,
            last_fragment,
            width,
            height,
            camera_angle,
        )
        if completed_frame is None:
            return

        jpeg, completed_frame_id, completed_width, completed_height, completed_camera_angle = completed_frame
        if not jpeg.startswith(JPEG_SOI):
            self.dropped_frames += 1
            self.update_stats()
            return

        eoi = jpeg.rfind(JPEG_EOI)
        if eoi < 0:
            self.dropped_frames += 1
            self.logger.warning(f"Frame {completed_frame_id}: LAST without JPEG EOI")
            self.update_stats()
            return

        self.emit_jpeg(
            jpeg[: eoi + 2],
            completed_frame_id,
            completed_width,
            completed_height,
            camera_angle=completed_camera_angle,
        )

    def _update_motion_metadata(self, header: bytes) -> float | None:
        """Update gyro state and return the frame's relative rotation angle.

        Parameters
        ----------
        header : bytes
            Video transport header containing the packed motion word.

        Returns
        -------
        float | None
            Frame-relative rotation angle, or ``None`` when no angle is available.

        Raises
        ------
        struct.error
            If the header is too short to contain the motion word.
        """
        # The tested Soulear/YPC firmware packs orientation metadata into
        # one 32-bit little-endian word at bytes 6..9:
        # little-endian word at bytes 6..9:
        #
        #   bits  0.. 8 : magnitude A
        #   bit       9 : sign A
        #   bits 10..18 : magnitude B
        #   bit      19 : sign B
        #   bits 20..28 : magnitude C
        #   bit      29 : sign C
        #
        # A one-revolution calibration log showed that atan2(A, B) unwraps to
        # ~350 degrees, matching one physical turn almost exactly.
        motion_word = struct.unpack_from("<I", header, 6)[0]

        a_mag = motion_word & 0x1FF
        a_neg = (motion_word >> 9) & 0x01

        b_mag = (motion_word >> 10) & 0x1FF
        b_neg = (motion_word >> 19) & 0x01

        c_mag = (motion_word >> 20) & 0x1FF
        c_neg = (motion_word >> 29) & 0x01

        gyro_a = -a_mag if a_neg else a_mag
        gyro_b = -b_mag if b_neg else b_mag
        gyro_c = -c_mag if c_neg else c_mag

        self.gyro_xyz = (gyro_a, gyro_b, gyro_c)
        self.gyro_packet_count += 1

        if gyro_a != 0 or gyro_b != 0:
            raw_angle = math.degrees(math.atan2(gyro_a, gyro_b)) % 360.0

            # The packed sensor angle is already continuous. Only apply a
            # light wrap-aware low-pass filter; don't reject normal motion.
            self.raw_camera_angle = raw_angle
            if self.last_camera_angle is None:
                self.last_camera_angle = raw_angle
            else:
                delta = self.circular_delta_deg(
                    raw_angle,
                    self.last_camera_angle,
                )
                self.last_camera_angle = (self.last_camera_angle + (delta * 0.45)) % 360.0

            filtered_angle = self.last_camera_angle
            camera_angle = self.relative_auto_rotate_angle(filtered_angle)
        else:
            filtered_angle = self.last_camera_angle
            camera_angle = self.relative_auto_rotate_angle(filtered_angle)

        if self.debug and (self.video_packet_count % 200 == 0):
            self.logger.debug(
                f"MOTION_PACKED: A={gyro_a} B={gyro_b} C={gyro_c} "
                f"raw={self.raw_camera_angle:.1f}° "
                f"filtered={self.last_camera_angle:.1f}° "
                f"relative={camera_angle:.1f}°"
                if camera_angle is not None
                else f"MOTION_PACKED: A={gyro_a} B={gyro_b} C={gyro_c} angle=?"
            )

        return camera_angle

    def _collect_jpeg_fragment(
        self,
        data: bytes,
        packet_sequence: int,
        frame_id: int,
        last_fragment: bool,
        width: int,
        height: int,
        camera_angle: float | None,
    ) -> tuple[bytes, int | None, int, int, float | None] | None:
        """Append one fragment and return metadata when a frame is complete.

        Parameters
        ----------
        data : bytes
            JPEG data carried by the current video packet.
        packet_sequence : int
            Eight-bit sequence number from the video header.
        frame_id : int
            Camera frame identifier.
        last_fragment : bool
            Whether the packet marks the end of the frame.
        width : int
            Transport-header width in pixels.
        height : int
            Transport-header height in pixels.
        camera_angle : float | None
            Relative rotation angle captured for this frame.

        Returns
        -------
        tuple[bytes, int | None, int, int, float | None] | None
            Completed JPEG, frame ID, dimensions, and angle; ``None`` if more
            fragments are required or the frame is dropped.
        """
        with self.jpeg_lock:
            soi = data.find(JPEG_SOI)

            if soi >= 0:
                if self.collecting_jpeg and self.jpeg_buffer:
                    self.dropped_frames += 1
                    self.logger.debug("JPEG: vorherigen unvollständigen Frame verworfen")

                self.jpeg_buffer.clear()
                self.jpeg_buffer.extend(data[soi:])
                self.collecting_jpeg = True
                self.current_frame_id = frame_id
                self.expected_packet_sequence = (packet_sequence + 1) & 0xFF
                self.current_width = width
                self.current_height = height
                self.current_camera_angle = camera_angle
                if self.debug and (self.frame_count < 5 or self.frame_count % self.jpeg_log_every == 0):
                    self.logger.debug(f"JPEG START frame={frame_id} seq={packet_sequence} {width}x{height}")
            else:
                if not self.collecting_jpeg:
                    return

                if frame_id != self.current_frame_id:
                    self.dropped_frames += 1
                    self.logger.debug(f"JPEG frame jump {self.current_frame_id}->{frame_id}; drop")
                    self.reset_jpeg_locked()
                    self.update_stats()
                    return

                if self.expected_packet_sequence is not None and packet_sequence != self.expected_packet_sequence:
                    missing = self.sequence_gap(self.expected_packet_sequence, packet_sequence)
                    self.report_packet_loss(frame_id, self.expected_packet_sequence, packet_sequence, missing)
                    if missing:
                        self.send_nack(missing)
                    self.dropped_frames += 1
                    self.reset_jpeg_locked()
                    self.update_stats()
                    return

                self.jpeg_buffer.extend(data)
                self.expected_packet_sequence = (packet_sequence + 1) & 0xFF

            if len(self.jpeg_buffer) > MAX_JPEG_SIZE:
                self.dropped_frames += 1
                self.logger.warning("JPEG exceeded 5 MiB; frame dropped")
                self.reset_jpeg_locked()
                self.update_stats()
                return

            if not last_fragment:
                return None

            jpeg = bytes(self.jpeg_buffer)
            completed_frame_id = self.current_frame_id
            completed_width = self.current_width
            completed_height = self.current_height
            completed_camera_angle = getattr(self, "current_camera_angle", None)
            self.reset_jpeg_locked()
        return jpeg, completed_frame_id, completed_width, completed_height, completed_camera_angle

    def report_packet_loss(self, frame_id: int, expected: int, received: int, missing: list[int]) -> None:
        """Rate-limit packet-loss warnings while preserving a periodic summary."""
        self._packet_loss_events += len(missing)
        now = time.monotonic()
        if now - self._last_packet_loss_log_time < 10.0:
            return
        self.logger.warning(
            f"Video packet loss: {self._packet_loss_events} missing packets; latest frame={frame_id}, expected={expected}, received={received}"
        )
        self._packet_loss_events = 0
        self._last_packet_loss_log_time = now

    def reset_jpeg_locked(self) -> None:
        """Clear JPEG assembly state while holding ``jpeg_lock``."""
        self.jpeg_buffer.clear()
        self.collecting_jpeg = False
        self.current_frame_id = None
        self.expected_packet_sequence = None
        self.current_width = 0
        self.current_height = 0

    @staticmethod
    def sequence_gap(expected: int, received: int) -> list[int]:
        """List missing eight-bit packet sequence values before ``received``.

        Parameters
        ----------
        expected : int
            Sequence number expected next.
        received : int
            Sequence number observed in the incoming packet.

        Returns
        -------
        list[int]
            Up to 64 sequence numbers missing between the two values.
        """
        result = []
        value = expected & 0xFF
        for _ in range(64):
            if value == received:
                break
            result.append(value)
            value = (value + 1) & 0xFF
        return result

    # ------------------------------------------------------------------
    # Missing-packet NACK observed in native reassembly thread
    # ------------------------------------------------------------------

    def send_nack(self, missing_sequences: Sequence[int]) -> None:
        """Send a NACK requesting retransmission of missing packet sequences.

        Parameters
        ----------
        missing_sequences : Sequence[int]
            Missing eight-bit sequence values to include in the request.
        """
        missing = bytes(missing_sequences[:116])
        seq = self.next_sequence()
        packet = struct.pack("<IHIH", MAGIC, seq, CMD_NACK, len(missing)) + missing
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(packet, (self.camera_ip, CAMERA_CONTROL_PORT))
            sock.close()
            self.nack_count += 1
            self.logger.debug(f"NACK #{self.nack_count}: protocol-seq={seq} missing={list(missing)}")
        except OSError as exc:
            self.logger.debug(f"NACK error: {exc}")

    # ------------------------------------------------------------------
    # Complete JPEG
    # ------------------------------------------------------------------

    def emit_jpeg(
        self,
        jpeg: bytes,
        frame_id: int | str | None,
        width: int,
        height: int,
        camera_angle: float | None = None,
    ) -> None:
        """Publish one complete JPEG.

        width/height are from the Soulear 16-byte transport header. The client
        separately parses the JPEG SOF marker because this camera advertises
        640x480 in the transport header while the actual JPEG is 480x480.

        Parameters
        ----------
        jpeg : bytes
            Complete encoded JPEG frame.
        frame_id : int | str | None
            Camera frame identifier or legacy stream identifier.
        width : int
            Width advertised by the transport header.
        height : int
            Height advertised by the transport header.
        camera_angle : float | None, optional
            Relative angle associated with this frame.
        """
        self.frame_count += 1
        self.last_jpeg = jpeg
        self.last_jpeg_angle = camera_angle

        transport_resolution = (int(width), int(height))
        self.last_transport_resolution = transport_resolution
        jpeg_width, jpeg_height = self.jpeg_dimensions(jpeg)
        jpeg_resolution = (jpeg_width, jpeg_height) if jpeg_width > 0 and jpeg_height > 0 else transport_resolution

        self.last_jpeg_resolution = jpeg_resolution

        # Real receive rate over approximately one-second windows.
        now = time.monotonic()
        if self.fps_window_start is None:
            self.fps_window_start = now
            self.fps_window_frames = 1
        else:
            self.fps_window_frames += 1
            elapsed = now - self.fps_window_start
            if elapsed >= 1.0:
                self.fps_average = self.fps_window_frames / elapsed
                self.fps_window_frames = 0
                self.fps_window_start = now

        if jpeg_resolution != transport_resolution:
            resolution_text = (
                f"JPEG={jpeg_resolution[0]}x{jpeg_resolution[1]} "
                f"(Transport={transport_resolution[0]}x{transport_resolution[1]})"
            )
        else:
            resolution_text = f"{jpeg_resolution[0]}x{jpeg_resolution[1]}"

        resolution_changed = jpeg_resolution != self._last_logged_jpeg_resolution
        if resolution_changed:
            self.logger.info(f"Video stream active: {resolution_text}")
            self._last_logged_jpeg_resolution = jpeg_resolution
        elif self.frame_count <= 10 or self.frame_count % self.jpeg_log_every == 0:
            self.logger.debug(
                f"JPEG #{self.frame_count}: frame={frame_id} "
                f"{len(jpeg):,} Bytes {resolution_text} "
                f"RX_FPS={self.fps_average:.1f}"
            )

        # Recording gets the dimensions of the JPEG that is actually written.
        self._record_jpeg(
            jpeg,
            jpeg_resolution[0],
            jpeg_resolution[1],
            camera_angle,
        )

        #  enqueue complete JPEGs for the fixed-rate preview player.
        # deque(maxlen=12) guarantees bounded latency even if the camera bursts.
        with self.gui_frame_lock:
            self.gui_frame_queue.append((jpeg, camera_angle))

        if self.camera_recording:
            self.signals.status.emit(
                f"Recording - JPEG {jpeg_resolution[0]}x{jpeg_resolution[1]} "
                f"(Transport {transport_resolution[0]}x{transport_resolution[1]}) "
                f"- Frame {self.record_frame_count}"
            )
        else:
            if jpeg_resolution != transport_resolution:
                self.signals.status.emit(
                    f"Live - JPEG {jpeg_resolution[0]}x{jpeg_resolution[1]} "
                    f"(Transport {transport_resolution[0]}x{transport_resolution[1]})"
                )
            else:
                self.signals.status.emit(f"Live - {jpeg_resolution[0]}x{jpeg_resolution[1]}")

        self.update_stats()

    def update_stats(self) -> None:
        """Publish current frame, packet, orientation, LED, and recording statistics."""
        jpeg_res = (
            f"{self.last_jpeg_resolution[0]}x{self.last_jpeg_resolution[1]}" if self.last_jpeg_resolution else "?"
        )
        transport_res = (
            f"{self.last_transport_resolution[0]}x{self.last_transport_resolution[1]}"
            if self.last_transport_resolution
            else "?"
        )
        self.signals.stats.emit(
            f"Frames: {self.frame_count}    "
            f"Video-Pakete: {self.video_packet_count}    "
            f"Verworfen: {self.dropped_frames}    "
            f"NACKs: {self.nack_count}    "
            f"RX-FPS: {self.fps_average:.1f}    "
            f"JPEG: {jpeg_res}    "
            f"Transport: {transport_res}    "
            f"Preview: 20 Hz buffered    "
            f"Angle: {self.last_camera_angle:.1f}° "
            f"{'AUTO' if self.auto_rotate else 'off'}    "
            f"LED: {self.led_status if self.led_status is not None else '?'}    "
            f"REC: {'ON' if self.camera_recording else 'off'}"
        )

    # ------------------------------------------------------------------
    # Watchdog / fallback
    # ------------------------------------------------------------------

    def watchdog_loop(self) -> None:
        """Retry stream opening after startup failure or a sustained packet stall.

        Raises
        ------
        OSError
            If a fallback or reopen command cannot use its UDP socket.
        """
        # Give normal proOpenVideo time to answer and produce data.
        if not self.first_video_event.wait(1.0) and self.running and self.fallback_force:
            self.logger.warning("No video after normal open; trying the force-open fallback once")
            try:
                self.open_video_force("no-video-fallback")
            except OSError:
                self.logger.exception("Force-open fallback failed")
                return

        while self.running:
            time.sleep(0.25)
            if not self.auto_reopen:
                continue
            if self.reconfiguring:
                continue
            last = self.last_video_packet_time
            if last is None:
                continue
            idle = time.monotonic() - last
            if idle < 1.5:
                continue
            now = time.monotonic()
            if now - self.last_reopen_time < 3.0:
                continue

            self.last_reopen_time = now
            self.logger.warning(f"Video stream stalled for {idle:.1f}s; reopening")
            try:
                self.open_video_normal("watchdog")
            except OSError:
                self.logger.exception("Video stream reopen failed")
                return

    # ------------------------------------------------------------------
    # Save frame
    # ------------------------------------------------------------------

    def save_current_frame(self) -> None:
        """Save the most recently received JPEG, applying auto-rotation if enabled.

        Raises
        ------
        OSError
            If the output image cannot be created or written.
        """
        if self.last_jpeg is None:
            self.signals.status.emit("Noch kein Bild vorhanden")
            return

        jpeg = self.last_jpeg
        angle = self.last_jpeg_angle
        if self.auto_rotate:
            jpeg = self._transform_jpeg_for_export(jpeg, angle)

        filename = time.strftime("soulear_%Y-%m-%d_%H-%M-%S.jpg")
        with open(filename, "wb") as handle:
            handle.write(jpeg)
        suffix = " (auto-rotiert)" if self.auto_rotate else ""
        self.signals.status.emit(f"Gespeichert: {os.path.abspath(filename)}{suffix}")

    # ------------------------------------------------------------------
    # Start / stop
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Initialize sockets and threads, then open the camera video stream."""
        if self.running:
            return
        self.running = True
        self.camera_connected = False

        try:
            self.create_native_sockets()

            # Start the receive backend before the first OPEN_VIDEO command.
            # Normal operation needs no packet-capture privileges or interface.
            if self.use_dumpcap:
                self.capture_thread = threading.Thread(
                    target=self.capture_loop,
                    daemon=True,
                )
                self.capture_thread.start()
                time.sleep(0.4)
            else:
                self.start_socket_receivers()
                time.sleep(0.05)

            if self.keepalives_enabled:
                self.send_ne7_probe()
                time.sleep(0.15)

            if self.keepalives_enabled:
                self.keepalive_thread = threading.Thread(
                    target=self.keepalive_loop,
                    daemon=True,
                )
                self.keepalive_thread.start()

            online = self.camera_check_online()

            if online and self.status_payload is not None and self.capabilities_byte & 0x10:
                self.set_camera_time()

            # Native proOpenVideo (0x00010004)
            self.open_video_normal("initial")

            if self.online_monitor_enabled:
                self.online_thread = threading.Thread(
                    target=self.online_monitor_loop,
                    daemon=True,
                )
                self.online_thread.start()

            self.watchdog_thread = threading.Thread(
                target=self.watchdog_loop,
                daemon=True,
            )
            self.watchdog_thread.start()

        except OSError as exc:
            self.logger.log(
                logging.ERROR,
                "START ERROR: network setup failed for local IP %s: %s",
                self.local_ip,
                exc,
            )
            self.signals.status.emit(f"Startfehler: {exc}")
            self.stop()
        except Exception as exc:
            self.logger.exception("START ERROR")
            self.signals.status.emit(f"Startfehler: {exc}")
            self.stop()

    def stop(self) -> None:
        """Stop recording, close sockets, and terminate optional capture."""
        if self.camera_recording or self.record_ffmpeg is not None:
            try:
                self.stop_video_recording()
            except Exception:
                self.logger.exception("RECORD_STOP during shutdown failed")

        if not self.running:
            self.camera_connected = False
            return
        self.running = False
        self.camera_connected = False
        self.logger.info("Stopping Soulear...")

        for sock in (
            self.video_socket,
            self.video2_socket,
            self.presence_video_socket,
            self.presence_control1_socket,
            self.presence_control2_socket,
        ):
            if sock is not None:
                with suppress(OSError):
                    sock.close()

        if self.dumpcap_process is not None:
            try:
                self.dumpcap_process.terminate()
                self.dumpcap_process.wait(timeout=1.5)
            except Exception:
                with suppress(Exception):
                    self.dumpcap_process.kill()
            self.dumpcap_process = None

        self.logger.info("Soulear stopped.")


# ======================================================================
# GUI
# ======================================================================


class MainWindow(QMainWindow):
    """Present the live camera preview and its recording/control actions."""

    def __init__(self, args: argparse.Namespace) -> None:
        """Build the camera window from parsed command-line options.

        Parameters
        ----------
        args : argparse.Namespace
            Parsed camera, network, and runtime options.
        """
        super().__init__()
        self.setWindowTitle("Soulear Linux Camera")
        self.resize(800, 700)
        self.current_pixmap = None

        self.image_label = QLabel("Warte auf Soulear …")
        self.image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.image_label.setMinimumSize(640, 480)

        self.status_label = QLabel("Initialisiere …")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.stats_label = QLabel("Frames: 0")
        self.stats_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.save_button = QPushButton("Bild speichern")
        self.save_button.setEnabled(False)

        self.record_start_button = QPushButton("Videoaufnahme starten")
        self.record_start_button.setEnabled(True)
        self.record_stop_button = QPushButton("Videoaufnahme stoppen")
        self.record_stop_button.setEnabled(False)

        self.led_on_button = QPushButton("LED an")
        self.led_off_button = QPushButton("LED aus")

        self.auto_rotate_button = QPushButton("Auto-Rotation: AUS")
        self.auto_rotate_button.setCheckable(True)
        self.auto_rotate_button.setChecked(False)

        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(self.save_button)
        button_layout.addWidget(self.record_start_button)
        button_layout.addWidget(self.record_stop_button)
        button_layout.addWidget(self.led_on_button)
        button_layout.addWidget(self.led_off_button)
        button_layout.addWidget(self.auto_rotate_button)
        button_layout.addStretch()

        layout = QVBoxLayout()
        layout.addWidget(self.image_label, stretch=1)
        layout.addWidget(self.status_label)
        layout.addWidget(self.stats_label)
        layout.addLayout(button_layout)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.signals = Signals()
        self.signals.status.connect(self.status_label.setText)
        self.signals.stats.connect(self.stats_label.setText)
        self.signals.recording_state.connect(self.set_recording_ui_state)

        self.camera = SoulearCamera(
            interface=args.interface,
            use_dumpcap=args.dumpcap,
            local_ip=args.local_ip,
            camera_ip=args.camera_ip,
            broadcast_ip=args.broadcast_ip,
            signals=self.signals,
            debug=args.loglevel == "DEBUG",
            keepalives=not args.no_keepalive,
            online_monitor=not args.no_online_monitor,
            fallback_force=not args.no_force_fallback,
            auto_reopen=not args.no_auto_reopen,
        )
        self.save_button.clicked.connect(self.camera.save_current_frame)
        self.record_start_button.clicked.connect(self.start_recording)
        self.record_stop_button.clicked.connect(self.stop_recording)
        self.led_on_button.clicked.connect(lambda: self.set_led(True))
        self.led_off_button.clicked.connect(lambda: self.set_led(False))
        self.auto_rotate_button.toggled.connect(self.set_auto_rotate)

        #  play the live JPEG FIFO at the same 20 fps cadence used by
        # the successful local recording.  This intentionally smooths camera
        # packet/frame jitter instead of displaying each arrival immediately.
        self.preview_timer = QTimer(self)
        self.preview_timer.setTimerType(Qt.TimerType.PreciseTimer)
        self.preview_timer.setInterval(50)  # 20 Hz
        self.preview_timer.timeout.connect(self.display_recording_style_frame)
        self.preview_timer.start()

        threading.Thread(target=self.camera.start, daemon=True).start()

    def start_recording(self) -> None:
        """Start recording on a worker thread and update the window state."""
        self.record_start_button.setEnabled(False)
        self.record_stop_button.setEnabled(True)
        self.auto_rotate_button.setEnabled(False)
        self.status_label.setText("Starte Kamera-Recording …")

        def worker() -> None:
            """Run the blocking recording startup and report its result."""
            ok = self.camera.start_video_recording()
            if ok:
                self.signals.recording_state.emit(True)
                mode = "auto-rotiert" if self.camera.record_auto_rotate else "original"
                self.signals.status.emit(f"Videoaufnahme gestartet - {mode}; Auto-Rotation bis zum Stop gesperrt")
            else:
                self.signals.status.emit("Lokale Videoaufnahme konnte nicht gestartet werden")
                self.signals.recording_state.emit(False)

        threading.Thread(target=worker, daemon=True).start()

    def stop_recording(self) -> None:
        """Stop recording asynchronously and restore recording controls."""
        self.record_stop_button.setEnabled(False)
        self.status_label.setText("Stoppe Kamera-Recording …")

        def worker() -> None:
            """Stop the camera recording and publish completion status."""
            self.camera.stop_video_recording()
            self.signals.status.emit("Recording beendet")
            self.signals.recording_state.emit(False)

        threading.Thread(target=worker, daemon=True).start()

    def set_recording_ui_state(self, active: bool) -> None:
        """Enable or disable recording controls for the current state.

        Parameters
        ----------
        active : bool
            Whether a recording is active.
        """
        active = bool(active)
        self.record_start_button.setEnabled(not active)
        self.record_stop_button.setEnabled(active)
        self.auto_rotate_button.setEnabled(not active)

    def set_led(self, enabled: bool) -> None:
        """Set the camera LED asynchronously and publish the command result.

        Parameters
        ----------
        enabled : bool
            True to turn the LED on, false to turn it off.
        """
        self.led_on_button.setEnabled(False)
        self.led_off_button.setEnabled(False)

        def worker() -> None:
            """Send the LED command and restore the button state."""
            ok = self.camera.set_led(enabled)
            if ok:
                self.signals.status.emit("LED eingeschaltet" if enabled else "LED ausgeschaltet")
            else:
                self.signals.status.emit("LED-Befehl fehlgeschlagen")
            self.led_on_button.setEnabled(True)
            self.led_off_button.setEnabled(True)

        threading.Thread(target=worker, daemon=True).start()

    def set_auto_rotate(self, enabled: bool) -> None:
        """Enable or disable orientation correction for preview and exports.

        Parameters
        ----------
        enabled : bool
            Whether to counter-rotate frames using the camera motion sensor.
        """
        if self.camera.camera_recording:
            # The recording pipeline freezes its orientation mode at start.
            # Reject programmatic/user changes while the file is open too.
            self.auto_rotate_button.blockSignals(True)
            self.auto_rotate_button.setChecked(self.camera.auto_rotate)
            self.auto_rotate_button.blockSignals(False)
            self.signals.status.emit("Auto-Rotation kann während einer Videoaufnahme nicht geändert werden")
            return

        self.camera.auto_rotate = bool(enabled)
        if enabled:
            self.camera.auto_rotate_zero = self.camera.last_camera_angle
        else:
            self.camera.auto_rotate_zero = None

        self.auto_rotate_button.setText("Auto-Rotation: AN" if enabled else "Auto-Rotation: AUS")
        angle = self.camera.last_camera_angle
        if enabled:
            self.signals.status.emit(
                "Auto-Rotation aktiviert - gepackter Soulear-Sensorwinkel"
                + (f" - Winkel {angle}°" if angle is not None else "")
            )
        else:
            self.signals.status.emit("Auto-Rotation deaktiviert")

    def display_recording_style_frame(self) -> None:
        """Play the live stream like the MJPEG recording: fixed 20 Hz.

        We initially buffer four frames (~200 ms).  That trades a small amount
        of latency for a much more regular cadence.  If the camera temporarily
        falls below 20 fps, the last displayed frame is repeated instead of
        making the GUI stall.  If a burst grows too large, old frames are
        discarded to keep latency bounded.
        """
        item = None

        with self.camera.gui_frame_lock:
            q = self.camera.gui_frame_queue

            if not self.camera.gui_preview_started:
                if len(q) < self.camera.gui_preview_target_buffer:
                    return
                self.camera.gui_preview_started = True
                self.camera.logger.info(f"PREVIEW20: Start mit {len(q)} gepufferten Frames")

            # A receive burst can briefly outrun the 20-Hz player. Keep only a
            # few recent frames so the preview never drifts seconds behind.
            if len(q) > self.camera.gui_preview_max_latency_frames:
                target = self.camera.gui_preview_target_buffer
                dropped = 0
                while len(q) > target:
                    q.popleft()
                    dropped += 1
                self.camera.logger.debug(f"PREVIEW20: {dropped} alte Frames verworfen (Latenzbegrenzung)")

            if q:
                item = q.popleft()
                self.camera.gui_last_frame = item
            else:
                # Same idea as a constant-rate video timeline: hold the most
                # recent frame until the next camera frame arrives.
                item = self.camera.gui_last_frame

        if item is not None:
            jpeg, camera_angle = item
            self.display_frame(jpeg, camera_angle)

    def display_frame(self, jpeg: bytes, camera_angle: float | None = None) -> None:
        """Decode and render one JPEG frame in the preview widget.

        Parameters
        ----------
        jpeg : bytes
            Encoded camera frame.
        camera_angle : float | None, optional
            Relative rotation angle in degrees for auto-rotated display.
        """
        image = QImage.fromData(jpeg, format="JPEG")  # ty: ignore[invalid-argument-type]
        if image.isNull():
            self.camera.logger.error("Qt could not decode JPEG frame")
            return

        pixmap = QPixmap.fromImage(image)

        if self.camera.auto_rotate and camera_angle is not None:
            #  show only the centered circular region that is guaranteed
            # to exist for every rotation.  Render into a FIXED square canvas
            # so the visible circle never changes size at 0/45/90 degrees.
            side = min(pixmap.width(), pixmap.height())
            rotated = QPixmap(side, side)
            rotated.fill(Qt.GlobalColor.transparent)

            painter = QPainter(rotated)
            painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, True)

            clip = QPainterPath()
            clip.addEllipse(QRectF(0.0, 0.0, float(side), float(side)))
            painter.setClipPath(clip)

            painter.translate(side / 2.0, side / 2.0)
            painter.rotate(-float(camera_angle))
            painter.drawPixmap(
                int(-pixmap.width() / 2),
                int(-pixmap.height() / 2),
                pixmap,
            )
            painter.end()

            pixmap = rotated

        self.current_pixmap = pixmap
        self.update_scaled_pixmap()
        self.save_button.setEnabled(True)

    def update_scaled_pixmap(self) -> None:
        """Scale the current preview image to fit the image widget."""
        if self.current_pixmap is None:
            return
        self.image_label.setPixmap(
            self.current_pixmap.scaled(
                self.image_label.size(),
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
        )

    def resizeEvent(self, event: QResizeEvent) -> None:
        """Rescale the preview after a Qt resize event.

        Parameters
        ----------
        event : QResizeEvent
            Qt event describing the new window size.
        """
        super().resizeEvent(event)
        self.update_scaled_pixmap()

    def closeEvent(self, event: QCloseEvent) -> None:
        """Stop camera resources before accepting the window-close event.

        Parameters
        ----------
        event : QCloseEvent
            Qt close event to accept after shutdown.
        """
        self.camera.stop()
        event.accept()


# ======================================================================
# Main
# ======================================================================


def main() -> None:
    """Parse command-line options and run the Qt camera application.

    Returns
    -------
    None

    Raises
    ------
    SystemExit
        When argparse handles help/version output or Qt exits the application.

    """
    parser = argparse.ArgumentParser(description="Linux client for Soulear/YPC Wi-Fi inspection cameras")
    parser.add_argument(
        "--dumpcap",
        action="store_true",
        help="Use optional dumpcap packet capture instead of normal UDP sockets",
    )
    parser.add_argument(
        "--interface",
        "-i",
        default=None,
        help="Interface for --dumpcap. If omitted, it is detected via the route to --camera-ip",
    )
    parser.add_argument(
        "--local-ip",
        default="192.168.1.10",
        help="Local IPv4 address used for UDP sockets (default: 192.168.1.10)",
    )
    parser.add_argument(
        "--camera-ip",
        "--camera",
        dest="camera_ip",
        default="192.168.1.1",
        help="Camera IPv4 address (default: 192.168.1.1)",
    )
    parser.add_argument(
        "--broadcast-ip",
        "--broadcast",
        dest="broadcast_ip",
        default="192.168.1.255",
        help="Broadcast IPv4 address used by presence keepalives (default: 192.168.1.255)",
    )
    parser.add_argument(
        "-l",
        "--loglevel",
        type=str.upper,
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        default="INFO",
        metavar="LEVEL",
        help="Set logging level (default: INFO)",
    )
    parser.add_argument("--no-keepalive", action="store_true", help="Disable legacy presence keepalives")
    parser.add_argument("--no-online-monitor", action="store_true", help="Disable periodic CHECK_ONLINE")
    parser.add_argument(
        "--no-force-fallback",
        action="store_true",
        help="Disable OPEN_VIDEO_FORCE fallback",
    )
    parser.add_argument("--no-auto-reopen", action="store_true", help="Disable stream watchdog reopen")
    parser.add_argument("-V", "--version", action="version", version=f"hopefox-ypc-linux {__version__}")
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.loglevel),
        format="%(levelname)s: %(message)s",
    )

    app = QApplication(sys.argv)
    window = MainWindow(args)
    window.show()
    signal.signal(signal.SIGINT, lambda _signum, _frame: window.close())
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
