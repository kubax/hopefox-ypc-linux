#!/usr/bin/env python3

import argparse
import math
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import deque

from PySide6.QtCore import QObject, Qt, Signal, QTimer, QRectF, QBuffer, QByteArray, QIODevice
from PySide6.QtGui import QImage, QPixmap, QPainter, QPainterPath
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QSlider,
    QVBoxLayout,
    QWidget,
)


# ======================================================================
# Soulear protocol constants (confirmed/documented behaviour)
# ======================================================================

MAGIC = 0xFFEEFFEE

CMD_CHECK_ONLINE = 0x00010001
CMD_OPEN_VIDEO = 0x00010004          # internal proOpenVideo (normal stream)
CMD_OPEN_VIDEO_FORCE = 0x00010016    # exported openVideoForceApi
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
    frame = Signal(bytes)
    status = Signal(str)
    stats = Signal(str)
    recording_state = Signal(bool)


# ======================================================================
# Classic PCAP reader for dumpcap -F pcap -w -
# ======================================================================

class PcapStreamReader:
    def __init__(self, stream):
        self.stream = stream
        self.endian = None
        self.linktype = None

    def read_exact(self, size):
        result = bytearray()
        while len(result) < size:
            chunk = self.stream.read(size - len(result))
            if not chunk:
                return None
            result.extend(chunk)
        return bytes(result)

    def read_global_header(self):
        header = self.read_exact(24)
        if header is None:
            raise RuntimeError("dumpcap lieferte keinen PCAP-Header")

        magic = header[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            self.endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            self.endian = ">"
        else:
            raise RuntimeError(f"Unbekanntes PCAP-Format: {magic.hex(' ')}")

        _, _, _, _, _, self.linktype = struct.unpack(
            self.endian + "HHIIII", header[4:24]
        )
        if self.linktype != 1:
            raise RuntimeError(
                f"Unerwarteter PCAP-Linktype {self.linktype}; Ethernet (1) erwartet"
            )

    def packets(self):
        self.read_global_header()
        while True:
            packet_header = self.read_exact(16)
            if packet_header is None:
                return
            _, _, captured_len, _ = struct.unpack(
                self.endian + "IIII", packet_header
            )
            packet = self.read_exact(captured_len)
            if packet is None:
                return
            yield packet


# ======================================================================
# Soulear client
# ======================================================================

class SoulearCamera:
    def __init__(
        self,
        interface,
        use_dumpcap,
        local_ip,
        camera_ip,
        broadcast_ip,
        signals,
        debug=False,
        keepalives=True,
        online_monitor=True,
        fallback_force=True,
        auto_reopen=True,
    ):
        self.interface = interface
        self.use_dumpcap = bool(use_dumpcap)
        self.local_ip = local_ip
        self.camera_ip = camera_ip
        self.broadcast_ip = broadcast_ip
        self.signals = signals
        self.debug = debug
        self.keepalives_enabled = keepalives
        self.online_monitor_enabled = online_monitor
        self.fallback_force = fallback_force
        self.auto_reopen = auto_reopen

        self.running = False
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
        self.last_camera_angle = None          # filtered absolute angle
        self.raw_camera_angle = None
        self.auto_rotate_zero = None           # angle at enable time
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

    def log(self, *args):
        print(*args, flush=True)

    def dbg(self, *args):
        if self.debug:
            print(*args, flush=True)

    def next_sequence(self):
        with self.seq_lock:
            value = self.protocol_sequence
            self.protocol_sequence = (self.protocol_sequence + 1) & 0xFFFF
            if self.protocol_sequence == 0:
                self.protocol_sequence = 1
            return value

    # ------------------------------------------------------------------
    # Sockets
    # ------------------------------------------------------------------

    def make_dynamic_socket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.local_ip, 0))
        sock.settimeout(0.2)
        return sock

    def make_bound_broadcast_socket(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind((self.local_ip, port))
        sock.settimeout(0.2)
        return sock

    def create_native_sockets(self):
        self.video_socket = self.make_dynamic_socket()
        self.video2_socket = self.make_dynamic_socket()
        self.video_port = self.video_socket.getsockname()[1]
        self.video2_port = self.video2_socket.getsockname()[1]

        self.log("Native-style UDP sockets")
        self.log("------------------------")
        self.log(f"Primary video port:   {self.video_port}")
        self.log(f"Secondary video port: {self.video2_port}")

        if self.keepalives_enabled:
            try:
                self.presence_video_socket = self.make_bound_broadcast_socket(
                    PRESENCE_VIDEO_PORT
                )
                self.presence_control1_socket = self.make_bound_broadcast_socket(
                    PRESENCE_CONTROL1_PORT
                )
                self.presence_control2_socket = self.make_bound_broadcast_socket(
                    PRESENCE_CONTROL2_PORT
                )
                self.log("Presence sockets:     44506, 52219, 52220")
            except OSError as exc:
                self.log(f"WARN: Presence-Sockets nicht vollständig verfügbar: {exc}")
                self.keepalives_enabled = False
        self.log()

    def _build_synthetic_udp_frame(self, src_ip, src_port, dst_port, payload):
        """Build the minimal Ethernet/IPv4/UDP envelope used by the common parser.

        This keeps the socket receiver and optional dumpcap backend on the same
        packet-processing path without requiring raw-socket privileges.
        """
        udp_len = 8 + len(payload)
        total_len = 20 + udp_len
        ethernet = (b"\x00" * 12) + b"\x08\x00"
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, total_len, 0, 0, 64, 17, 0,
            socket.inet_aton(src_ip),
            socket.inet_aton(self.local_ip),
        )
        udp_header = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
        return ethernet + ip_header + udp_header + payload

    def socket_receive_loop(self, sock, local_port, label):
        while self.running:
            try:
                payload, address = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            except Exception as exc:
                if self.running:
                    self.log(f"{label} receive error: {exc}")
                return

            src_ip, src_port = address[0], address[1]
            if src_ip != self.camera_ip:
                continue
            frame = self._build_synthetic_udp_frame(
                src_ip, src_port, local_port, payload
            )
            try:
                with self.packet_process_lock:
                    self.process_ethernet_frame(frame)
            except Exception as exc:
                if self.running:
                    self.log(f"{label} packet processing error: {exc}")
                    if self.debug:
                        import traceback
                        traceback.print_exc()

    def start_socket_receivers(self):
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
        self.log("UDP socket capture active (dumpcap not required)")

    # ------------------------------------------------------------------
    # Synchronous native-style command transaction
    # ------------------------------------------------------------------

    def sync_transaction(
        self,
        packet,
        destination_port,
        expected_seq,
        timeout=0.15,
        retries=4,
        label="COMMAND",
    ):
        # cameraRecordStatusSync uses a temporary UDP socket for the sync
        # exchange. Reproduce that behavior rather than retaining a command
        # socket between calls.
        with self.command_lock:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((self.local_ip, 0))
            sock.settimeout(timeout)
            local_port = sock.getsockname()[1]

            self.dbg(
                f"{label}: local UDP :{local_port} -> "
                f"{self.camera_ip}:{destination_port}  {packet.hex(' ')}"
            )

            try:
                for attempt in range(1, retries + 1):
                    try:
                        sock.sendto(packet, (self.camera_ip, destination_port))
                        response, address = sock.recvfrom(8192)
                    except socket.timeout:
                        self.dbg(f"{label}: timeout {attempt}/{retries}")
                        continue

                    if len(response) < 6:
                        self.dbg(f"{label}: short response {response.hex(' ')}")
                        continue

                    magic, seq = struct.unpack_from("<IH", response, 0)
                    if magic != MAGIC or seq != expected_seq:
                        self.dbg(
                            f"{label}: unrelated response from {address}: "
                            f"magic=0x{magic:08x} seq={seq}"
                        )
                        continue

                    self.dbg(
                        f"{label}: ACK/RX {len(response)} bytes from "
                        f"{address[0]}:{address[1]}  {response[:32].hex(' ')}"
                    )
                    return response
            finally:
                sock.close()

        return None

    # ------------------------------------------------------------------
    # cameraCheckOnline (0x00010001 -> UDP 10005)
    # ------------------------------------------------------------------

    def camera_check_online(self, quiet=False):
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

        if response is None:
            if not quiet:
                self.log("CHECK_ONLINE: keine Antwort (Open wird trotzdem versucht)")
            return False

        if not quiet:
            self.log(f"CHECK_ONLINE: Kamera antwortet ({len(response)} Bytes)")

        # Native cameraCheckOnline expects a 0x80-byte status block after a
        # 12-byte protocol header. Preserve it when available.
        if len(response) >= 12:
            payload_len = struct.unpack_from("<H", response, 10)[0]
            if payload_len == 0x80 and len(response) >= 12 + payload_len:
                self.status_payload = response[12:12 + payload_len]
                self.capabilities_byte = self.status_payload[124]
                self.dual_stream = bool(self.capabilities_byte & 0x20)
                if not quiet:
                    self.log(
                        "CHECK_ONLINE: 128-Byte-Status erhalten, "
                        f"cap[124]=0x{self.capabilities_byte:02x}, "
                        f"dual-stream={'ja' if self.dual_stream else 'nein'}, "
                        f"time-sync={'ja' if self.capabilities_byte & 0x10 else 'nein'}"
                    )
        return True

    # ------------------------------------------------------------------
    # LED / illumination
    # ------------------------------------------------------------------

    def get_led_status(self, op_type=1):
        """Read LED status using the exact APK LedStatusGet transport.

        Request:
          cmd 0x0001000A
          payload length 3
          payload: [opType, 0, 0]

        The native wrapper returns payload byte1 as ledStatus and byte2 as
        lightValue.
        """
        seq = self.next_sequence()
        payload = bytes([op_type & 0x0F, 0x00, 0x00])
        packet = struct.pack(
            "<IHIH",
            MAGIC,
            seq,
            CMD_LED_STATUS_GET,
            len(payload),
        ) + payload

        self.log(f"LED_GET: seq={seq} opType={op_type}")
        self.dbg(f"  TX: {packet.hex(' ')}")

        response = self.sync_transaction(
            packet,
            CAMERA_CONTROL_PORT,
            seq,
            timeout=0.25,
            retries=5,
            label="LED_GET",
        )
        if response is None or len(response) < 15:
            self.log("LED_GET: keine/zu kurze Antwort")
            return None

        magic, rseq = struct.unpack_from("<IH", response, 0)
        cmd_low = struct.unpack_from("<H", response, 6)[0]
        if (
            magic != MAGIC
            or rseq != seq
            or cmd_low != (CMD_LED_STATUS_GET & 0xFFFF)
        ):
            self.log(f"LED_GET: unerwarteter Header: {response.hex(' ')}")
            return None

        # Native parser checks byte 9 as firmware result for these generic
        # camera commands.
        fw_result = response[9]
        if fw_result != 0:
            self.log(f"LED_GET: Firmware-Fehler {fw_result}")
            return None

        payload_len = struct.unpack_from("<H", response, 10)[0]
        if payload_len < 3 or len(response) < 12 + payload_len:
            self.log(
                f"LED_GET: ungültige Payload-Länge {payload_len}: "
                f"{response.hex(' ')}"
            )
            return None

        rp = response[12:12 + payload_len]
        self.led_status = rp[1]
        self.led_value = rp[2]
        self.log(
            f"LED_GET: status={self.led_status}, value={self.led_value}"
        )
        return self.led_status, self.led_value

    def discover_led_op_type(self):
        """Probe the 4-bit LED operation type with read-only GET requests.

        The native transport masks opType to four bits. Firmware result code 3
        means "unsupported/invalid operation type" on this device.  We try
        0..15 and keep the first GET that succeeds.
        """
        if self.led_op_type is not None:
            return self.led_op_type

        self.log("LED_PROBE: teste opType 0..15 per GET")
        for op_type in range(16):
            result = self.get_led_status(op_type=op_type)
            if result is not None:
                self.log(
                    f"LED_PROBE: GET opType={op_type} lesbar "
                    f"(status={result[0]}, value={result[1]}); "
                    "das beweist noch keinen schreibbaren SET-Typ"
                )
                # Keep historical candidate 0 for diagnostic SET attempts,
                # but don't call it successfully discovered.
                self.led_op_type = op_type
                return op_type

        self.log("LED_PROBE: kein opType 0..15 wurde akzeptiert")
        return None

    def set_led(self, enabled):
        """Switch the scope illumination using the confirmed YPC payload."""
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
        packet = struct.pack(
            "<IHIH",
            MAGIC,
            seq,
            CMD_LED_STATUS_SET,
            len(payload),
        ) + payload

        label = "LED_ON" if enabled else "LED_OFF"
        self.log(
            f"{label}: seq={seq} opType={op_type} "
            f"ledStatus={led_status} value={light_value} "
            f"(3-Byte native payload via cmd 0x0001000A)"
        )
        self.dbg(f"  TX: {packet.hex(' ')}")

        response = self.sync_transaction(
            packet,
            CAMERA_CONTROL_PORT,
            seq,
            timeout=0.25,
            retries=5,
            label=label,
        )
        if response is None or len(response) < 10:
            self.log(f"{label}: keine gültige Antwort")
            return False

        magic, rseq = struct.unpack_from("<IH", response, 0)
        cmd_low = struct.unpack_from("<H", response, 6)[0]
        if (
            magic != MAGIC
            or rseq != seq
            or cmd_low != (CMD_LED_STATUS_SET & 0xFFFF)
        ):
            self.log(f"{label}: unerwarteter Header: {response.hex(' ')}")
            return False

        fw_result = response[9]
        if fw_result != 0:
            self.log(
                f"{label}: Firmware-Fehler {fw_result}; "
                f"Antwort={response.hex(' ')}"
            )
            return False

        self.led_status = led_status
        self.led_value = light_value
        self.log(f"{label}: bestätigt")
        return True

    # ------------------------------------------------------------------
    # Export image transformation
    # ------------------------------------------------------------------

    def _transform_jpeg_for_export(self, jpeg, camera_angle):
        """Return the preview-style rotated/circular JPEG for file export.

        The angle belongs to the same completed camera frame as *jpeg*.
        JPEG has no alpha channel, therefore pixels outside the circular
        viewport are rendered black.
        """
        if camera_angle is None:
            return jpeg

        image = QImage.fromData(jpeg, "JPEG")
        if image.isNull():
            self.log("EXPORT_ROTATE: JPEG konnte nicht dekodiert werden")
            return jpeg

        side = min(image.width(), image.height())
        output = QImage(side, side, QImage.Format_RGB32)
        output.fill(Qt.black)

        painter = QPainter(output)
        painter.setRenderHint(QPainter.SmoothPixmapTransform, True)

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
        if not buffer.open(QIODevice.WriteOnly):
            self.log("EXPORT_ROTATE: QBuffer konnte nicht geöffnet werden")
            return jpeg
        ok = output.save(buffer, "JPEG", 95)
        buffer.close()
        if not ok:
            self.log("EXPORT_ROTATE: JPEG-Encoding fehlgeschlagen")
            return jpeg
        return bytes(encoded)

    # ------------------------------------------------------------------
    # Camera recording state (native proRecordStatusSync)
    # ------------------------------------------------------------------

    def camera_record_status_sync(self, recording):
        """Try the optional camera-side recording-status sync command.

        The tested YPC camera rejects this optional status-sync feature with
        result code 2. Local recording does not depend on it.
        """
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
        self.log(
            f"{label}: seq={seq} status={status} -> "
            f"{self.camera_ip}:{CAMERA_CONTROL_PORT}"
        )
        self.dbg(f"  TX: {packet.hex(' ')}")

        response = self.sync_transaction(
            packet,
            CAMERA_CONTROL_PORT,
            seq,
            timeout=0.25,
            retries=5,
            label=label,
        )
        if response is None or len(response) < 10:
            self.log(f"{label}: keine gültige Antwort")
            self.record_remote_error = "timeout"
            return False

        magic, rseq = struct.unpack_from("<IH", response, 0)
        cmd_low = struct.unpack_from("<H", response, 6)[0]
        expected_low = CMD_RECORD_STATUS_SYNC & 0xFFFF
        firmware_result = response[9]
        echoed_status = response[12] if len(response) >= 13 else None

        if magic != MAGIC or rseq != seq or cmd_low != expected_low:
            self.log(
                f"{label}: Antwortheader passt nicht "
                f"magic=0x{magic:08x} seq={rseq} "
                f"cmd_low=0x{cmd_low:04x}"
            )
            self.record_remote_error = "bad-header"
            return False

        if firmware_result != 0:
            self.log(
                f"{label}: Firmware lehnt optionalen RecordStatusSync ab "
                f"(code={firmware_result}, echoed_status={echoed_status}). "
                "Lokale Videoaufnahme läuft trotzdem."
            )
            self.record_remote_error = firmware_result
            return False

        self.log(
            f"{label}: ACK bestätigt "
            f"(echoed_status={echoed_status})"
        )
        self.record_remote_error = None
        return True

    def _record_filename(self):
        stamp = time.strftime("%Y%m%d-%H%M%S")
        return os.path.abspath(f"soulear-recording-{stamp}.mkv")

    def start_video_recording(self):
        with self.record_lock:
            if self.camera_recording:
                self.log("RECORD_START: Aufnahme läuft bereits")
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
                self.log(
                    "RECORD_START: ffmpeg nicht gefunden; "
                    "keine lokale Videodatei möglich."
                )
                return True

            cmd = [
                ffmpeg,
                "-hide_banner",
                "-loglevel", "error",
                "-y",
                "-f", "image2pipe",
                "-framerate", str(self.record_fps),
                "-vcodec", "mjpeg",
                "-i", "pipe:0",
                "-an",
            ]
            # Input is MJPEG in both modes. Auto-rotation re-encodes each
            # source frame once in _transform_jpeg_for_export(); ffmpeg only
            # muxes those JPEG frames into Matroska without another encode.
            cmd += ["-c:v", "copy", output]

            try:
                proc = subprocess.Popen(
                    cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    bufsize=0,
                )
            except Exception as exc:
                self.log(f"RECORD_START: ffmpeg konnte nicht starten: {exc}")
                self.camera_record_status_sync(False)
                return False

            self.record_ffmpeg = proc
            self.record_output_path = output
            self.camera_recording = True
            self.record_start_resolution = self.last_jpeg_resolution
            self.record_seen_resolutions = set()
            self.record_frame_count = 0

            self.log(
                f"RECORD_START: lokale Datei {output}; "
                f"Start-Preview={self.record_start_resolution}; "
                f"auto_rotate={'ja' if self.record_auto_rotate else 'nein'}; "
                f"remote_sync={'aktiv' if self.record_remote_active else 'nicht unterstützt'}"
            )
            return True

    def stop_video_recording(self):
        with self.record_lock:
            if not self.camera_recording and self.record_ffmpeg is None:
                self.log("RECORD_STOP: keine Aufnahme aktiv")
                return False

            if self.record_remote_active:
                remote_ok = self.camera_record_status_sync(False)
            else:
                remote_ok = False
                self.log(
                    "RECORD_SYNC_STOP: übersprungen, weil Firmware den "
                    "RecordStatusSync beim Start nicht unterstützt hat."
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
                except Exception as exc:
                    self.log(f"RECORD_STOP: ffmpeg shutdown: {exc}")

                if proc.returncode not in (0, None):
                    try:
                        err = proc.stderr.read().decode("utf-8", "replace").strip()
                    except Exception:
                        err = ""
                    if err:
                        self.log(f"RECORD_STOP: ffmpeg: {err}")

            self.log(
                f"RECORD_STOP: frames={self.record_frame_count}, "
                f"Start={self.record_start_resolution}, "
                f"gesehen={sorted(self.record_seen_resolutions)}, "
                f"Datei={output or '-'}, "
                f"auto_rotate={'ja' if record_auto_rotate else 'nein'}, "
                f"remote_sync={'ja' if remote_was_active else 'unsupported'}, "
                f"remote_stop_ack={'ja' if remote_ok else 'nein'}"
            )
            return remote_ok

    def _record_jpeg(self, jpeg, width, height, camera_angle=None):
        with self.record_lock:
            if not self.camera_recording:
                return

            current = (int(width), int(height))
            self.record_seen_resolutions.add(current)
            self.record_frame_count += 1

            if (
                self.record_start_resolution
                and current != self.record_start_resolution
            ):
                self.log(
                    "RECORDING RESOLUTION CHANGE: "
                    f"{self.record_start_resolution} -> {width}x{height}"
                )
                self.record_start_resolution = current

            proc = self.record_ffmpeg
            if proc is None or proc.stdin is None:
                return

            export_jpeg = (
                self._transform_jpeg_for_export(jpeg, camera_angle)
                if self.record_auto_rotate
                else jpeg
            )

            try:
                proc.stdin.write(export_jpeg)
            except (BrokenPipeError, OSError) as exc:
                self.log(f"RECORD: ffmpeg pipe beendet: {exc}")
                try:
                    proc.stdin.close()
                except Exception:
                    pass
                self.record_ffmpeg = None

    # ------------------------------------------------------------------
    # Camera time
    # ------------------------------------------------------------------

    def set_camera_time(self):
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
            self.log("SET_TIME: bestätigt")
            return True
        self.log("SET_TIME: keine Bestätigung")
        return False

    # ------------------------------------------------------------------
    # Normal proOpenVideo (0x00010004 -> UDP 10006)
    # ------------------------------------------------------------------

    def open_video_normal(self, reason="initial"):
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

        self.log(
            f"OPEN_VIDEO(normal/{reason}): seq={seq} subtype={subtype} "
            f"primary={self.video_port} secondary={secondary}"
        )
        self.dbg(f"  TX: {packet.hex(' ')}")

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
            self.log(f"OPEN_VIDEO(normal): ACK ({len(response)} Bytes)")
            self.signals.status.emit("Normaler Videostream geöffnet")
            return True

        self.log("OPEN_VIDEO(normal): keine Bestätigung")
        return False

    # ------------------------------------------------------------------
    # Experimental native proOpenVideo variants
    # ------------------------------------------------------------------

    def open_video_force(self, reason="fallback"):
        seq = self.next_sequence()
        packet = struct.pack(
            "<IHIHH",
            MAGIC,
            seq,
            CMD_OPEN_VIDEO_FORCE,
            0,
            self.video_port,
        )
        self.log(
            f"OPEN_VIDEO_FORCE({reason}): seq={seq} video_port={self.video_port}"
        )
        self.dbg(f"  TX: {packet.hex(' ')}")
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
            self.log(f"OPEN_VIDEO_FORCE: ACK ({len(response)} Bytes)")
            self.signals.status.emit("Force-Videopfad geöffnet")
            return True
        self.log("OPEN_VIDEO_FORCE: keine Bestätigung")
        return False

    def send_ne7_probe(self):
        """One-shot discovery/legacy-stream probe based on haxko/NE3-Scope.

        Related NE7 firmware sends 66 39 01 01 to broadcast ports 58090 and
        46526, then 86 06 01 to 52219 and 20 36 to 44506.
        Our native Soulear library uses a close variant (66 30 01 01), so this
        is sent only once as a compatibility probe.
        """
        if not self.keepalives_enabled:
            return
        try:
            probe = bytes([0x66, 0x39, 0x01, 0x01])
            self.presence_control2_socket.sendto(
                probe, (self.broadcast_ip, 58090)
            )
            self.presence_control2_socket.sendto(
                probe, (self.broadcast_ip, 46526)
            )
            self.presence_control1_socket.sendto(
                KEEPALIVE_CONTROL1,
                (self.camera_ip, PRESENCE_CONTROL1_PORT),
            )
            self.presence_video_socket.sendto(
                KEEPALIVE_VIDEO,
                (self.camera_ip, PRESENCE_VIDEO_PORT),
            )
            self.log(
                "NE7 probe: 66 39 01 01 -> :58090/:46526; "
                "86 06 01 -> :52219; 20 36 -> :44506"
            )
        except OSError as exc:
            self.dbg(f"NE7 probe error: {exc}")

    def keepalive_loop(self):
        start = time.monotonic()
        next_control = start + 4.0
        next_video = start + 6.0

        while self.running:
            now = time.monotonic()
            if now >= next_control:
                try:
                    self.presence_control2_socket.sendto(
                        KEEPALIVE_CONTROL2,
                        (self.broadcast_ip, PRESENCE_CONTROL2_DEST),
                    )
                    self.presence_control1_socket.sendto(
                        KEEPALIVE_CONTROL1,
                        (self.broadcast_ip, PRESENCE_CONTROL1_PORT),
                    )
                    self.dbg(
                        "PRESENCE: 66 30 01 01 -> :46526; "
                        "86 06 01 -> :52219"
                    )
                except OSError as exc:
                    self.dbg(f"PRESENCE control error: {exc}")
                next_control = now + 1.0

            if now >= next_video:
                try:
                    self.presence_video_socket.sendto(
                        KEEPALIVE_VIDEO,
                        (self.broadcast_ip, PRESENCE_VIDEO_PORT),
                    )
                    self.dbg("PRESENCE: 20 36 -> :44506")
                except OSError as exc:
                    self.dbg(f"PRESENCE video error: {exc}")
                next_video = now + 3.0

            time.sleep(0.02)

    # ------------------------------------------------------------------
    # Periodic online check (the native info thread does this repeatedly)
    # ------------------------------------------------------------------

    def online_monitor_loop(self):
        # Do not collide with initial setup.
        time.sleep(2.0)
        while self.running:
            try:
                ok = self.camera_check_online(quiet=True)
                self.dbg(f"ONLINE monitor: {'ok' if ok else 'no response'}")
            except Exception as exc:
                self.dbg(f"ONLINE monitor error: {exc}")
            for _ in range(30):
                if not self.running:
                    return
                time.sleep(0.1)

    # ------------------------------------------------------------------
    # Optional dumpcap diagnostic capture
    # ------------------------------------------------------------------

    def detect_interface(self):
        if self.interface:
            return self.interface
        try:
            result = subprocess.run(
                ["ip", "route", "get", self.camera_ip],
                check=True, capture_output=True, text=True, timeout=2,
            )
            match = re.search(r"\bdev\s+(\S+)", result.stdout)
            if match:
                self.interface = match.group(1)
                return self.interface
        except Exception:
            pass
        raise RuntimeError(
            "dumpcap mode needs a network interface; use --interface"
        )

    def start_dumpcap(self):
        dumpcap = shutil.which("dumpcap")
        if dumpcap is None:
            raise RuntimeError(
                "dumpcap not found; install Wireshark CLI or run without --dumpcap"
            )
        interface = self.detect_interface()

        command = [
            dumpcap,
            "-q",
            "-F", "pcap",
            "-i", interface,
            "-s", "0",
            "-w", "-",
        ]
        self.log("Capture:", " ".join(command))
        self.dumpcap_process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        threading.Thread(
            target=self.dumpcap_stderr_loop,
            daemon=True,
        ).start()

    def dumpcap_stderr_loop(self):
        process = self.dumpcap_process
        if process is None or process.stderr is None:
            return
        for raw_line in process.stderr:
            line = raw_line.decode(errors="replace").strip()
            if line and self.debug:
                print(f"[dumpcap] {line}", flush=True)

    def capture_loop(self):
        try:
            self.start_dumpcap()
            process = self.dumpcap_process
            if process is None or process.stdout is None:
                raise RuntimeError("dumpcap stdout fehlt")

            reader = PcapStreamReader(process.stdout)
            self.log(f"Optional dumpcap capture active on {self.interface}")
            for ethernet_frame in reader.packets():
                if not self.running:
                    break
                self.process_ethernet_frame(ethernet_frame)
        except Exception as exc:
            if self.running:
                self.log(f"CAPTURE ERROR: {exc}")
                self.signals.status.emit(f"Capture-Fehler: {exc}")

    # ------------------------------------------------------------------
    # Ethernet / IPv4 / UDP parser
    # ------------------------------------------------------------------

    def decode_gyro_52219(self, src_port, dst_port, payload):
        """Decode the related NE7/Soulear gyro packet on UDP 52219.

        NE3-Scope/client2.py uses:
            struct.unpack(">BxBxBxxxxxxxxxxxxxHxxxx", data)

        The resulting values are x, y, z and a big-endian angle in degrees.
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
            if self.debug and (
                old is None
                or abs(angle - old) >= 2
                or self.gyro_packet_count <= 5
            ):
                self.log(
                    f"GYRO52219 #{self.gyro_packet_count}: "
                    f"x={x} y={y} z={z} angle={angle}° "
                    f"raw={payload[:25].hex(' ')}"
                )
        else:
            self.dbg(
                f"GYRO52219 #{self.gyro_packet_count}: "
                f"angle={angle} außerhalb 0..359, "
                f"raw={payload[:25].hex(' ')}"
            )

        return True

    def decode_notify_packet(self, src_port, dst_port, payload):
        """Decode the observed UDP/10007 command-9 notify envelope.

        Type 2 contains status/bit fields. It does not carry width/height and
        is not used as a resolution/open-video command by this client.
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
        body = payload[12:12 + declared_len]
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
                extra = (
                    f" ext9=0x{word9:04x} ext11=0x{byte11:02x} "
                    f"ext16=0x{byte16:02x}"
                )

            self.dbg(
                f"NOTIFY #{self.notify_packet_count} cmd=0x00000009 "
                f"type=2 len={declared_len} "
                f"status=0x{status_word:04x} "
                f"b0={bit0} bits1_7={bits1_7} b8={bit8} "
                f"bits9_15={bits9_15} field3={field3} field4={field4}"
                f"{extra}"
            )
        else:
            self.dbg(
                f"NOTIFY #{self.notify_packet_count} cmd=0x00000009 "
                f"type={notify_type} len={declared_len} "
                f"body={body[:32].hex(' ')}"
            )

        return True

    @staticmethod
    def jpeg_dimensions(jpeg):
        """Return (width, height) from JPEG SOF marker, or (0, 0)."""
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
                seglen = int.from_bytes(jpeg[i:i+2], "big")
                if seglen < 2 or i + seglen > n:
                    break
                if marker in (
                    0xC0, 0xC1, 0xC2, 0xC3,
                    0xC5, 0xC6, 0xC7,
                    0xC9, 0xCA, 0xCB,
                    0xCD, 0xCE, 0xCF,
                ):
                    if seglen >= 7:
                        h = int.from_bytes(jpeg[i+3:i+5], "big")
                        w = int.from_bytes(jpeg[i+5:i+7], "big")
                        return w, h
                i += seglen
        except Exception:
            pass
        return 0, 0

    def reset_legacy_frame(self, frame_number=None):
        self.legacy_frame_number = frame_number
        self.legacy_chunks = {}
        self.legacy_last_chunk = None

    def process_legacy_44506_packet(self, payload):
        """NE7-Scope compatible legacy transport.

        Header:
          byte0 frame_number
          byte1 flags (bit0 = final packet)
          byte2 chunk_number (1-based)
          byte3 flags2
        The final packet carries a 5-byte trailer after JPEG data.
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
                self.dbg(
                    f"LEGACY44506: frame jump {self.legacy_frame_number}"
                    f"->{frame_number}; old frame dropped"
                )
            self.reset_legacy_frame(frame_number)

        self.legacy_chunks[chunk_number - 1] = data

        if self.debug and (chunk_number == 1 or is_last):
            self.log(
                f"LEGACY44506 pkt#{self.legacy_packet_count}: "
                f"frame={frame_number} chunk={chunk_number} "
                f"flags=0x{flags:02x} flags2=0x{flags2:02x} "
                f"last={'yes' if is_last else 'no'} len={len(payload)}"
            )

        if not is_last:
            return

        self.legacy_last_chunk = chunk_number
        expected = set(range(chunk_number))
        present = set(self.legacy_chunks.keys())
        missing = sorted(expected - present)
        if missing:
            self.log(
                f"LEGACY44506: Frame {frame_number} unvollständig; "
                f"fehlende Chunks={[x + 1 for x in missing]}"
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
            jpeg = jpeg[:eoi + 2]

        if not jpeg.startswith(JPEG_SOI) or not jpeg.endswith(JPEG_EOI):
            self.log(
                f"LEGACY44506: Frame {frame_number} ist kein vollständiges JPEG "
                f"({len(jpeg)} Bytes)"
            )
            return

        width, height = self.jpeg_dimensions(jpeg)
        self.legacy_frame_count += 1
        self.log(
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

    def process_ethernet_frame(self, frame):
        if len(frame) < 14 + 20 + 8:
            return
        if frame[12:14] != b"\x08\x00":
            return

        ip_offset = 14
        version_ihl = frame[ip_offset]
        if version_ihl >> 4 != 4:
            return
        ihl = (version_ihl & 0x0F) * 4
        if ihl < 20 or len(frame) < ip_offset + ihl + 8:
            return
        if frame[ip_offset + 9] != 17:
            return

        src_ip = socket.inet_ntoa(frame[ip_offset + 12:ip_offset + 16])
        dst_ip = socket.inet_ntoa(frame[ip_offset + 16:ip_offset + 20])
        if src_ip != self.camera_ip:
            return

        udp_offset = ip_offset + ihl
        src_port, dst_port, udp_len = struct.unpack_from(
            "!HHH", frame, udp_offset
        )
        if udp_len < 8:
            return

        payload_offset = udp_offset + 8
        payload = frame[payload_offset:payload_offset + udp_len - 8]
        if not payload:
            return

        self.raw_packet_count += 1

        # Optional legacy gyro packets on UDP/52219 do not carry FFEEFFEE magic.
        if self.decode_gyro_52219(src_port, dst_port, payload):
            return

        # FFEE control ACKs may be visible on diagnostic capture; don't feed them
        # into the JPEG parser.
        if len(payload) >= 4 and payload[:4] == struct.pack("<I", MAGIC):
            if self.decode_notify_packet(src_port, dst_port, payload):
                return

            self.control_packet_count += 1
            self.dbg(
                f"RAW CONTROL #{self.control_packet_count}: "
                f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                f"len={len(payload)} {payload[:24].hex(' ')}"
            )
            return

        #  NE7-family legacy JPEG transport.  haxko/NE3-Scope client2.py
        # receives this on UDP 44506 with a 4-byte frame/chunk header.
        if src_port == PRESENCE_VIDEO_PORT and dst_port == PRESENCE_VIDEO_PORT:
            self.process_legacy_44506_packet(payload)
            return

        if len(payload) < VIDEO_HEADER_SIZE:
            return

        # Validate a Soulear video header rather than relying only on the
        # malformed UDP destination. Native receiver accepts types 1,2,5,6.
        stream_type = payload[0]
        if stream_type not in (1, 2, 5, 6):
            return

        width = struct.unpack_from("<H", payload, 12)[0]
        height = struct.unpack_from("<H", payload, 14)[0]
        if not (16 <= width <= 4096 and 16 <= height <= 4096):
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
            if self.debug and (
                now - self._last_stale_log_time >= 1.0
                or dst_port != self._last_stale_port
            ):
                self.log(
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

        if self.debug and (
            self.video_packet_count <= 10
            or self.video_packet_count % self.video_log_every == 0
        ):
            self.log(
                f"VIDEO #{self.video_packet_count:6d}: "
                f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                f"len={len(payload)} hdr={payload[:16].hex(' ')}"
            )

        self.process_video_packet(payload)

    # ------------------------------------------------------------------
    # Video/JPEG reassembly
    # ------------------------------------------------------------------

    @staticmethod
    def circular_delta_deg(new_angle, old_angle):
        """Shortest signed angular difference in [-180, 180)."""
        return ((new_angle - old_angle + 180.0) % 360.0) - 180.0

    def filter_camera_angle(self, raw_angle):
        """Wrap-aware stabilizer inspired by the native Soulear filtering."""
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

    def relative_auto_rotate_angle(self, filtered_angle):
        if filtered_angle is None:
            return None
        if self.auto_rotate_zero is None:
            self.auto_rotate_zero = filtered_angle
        return self.circular_delta_deg(filtered_angle, self.auto_rotate_zero)

    def process_video_packet(self, payload):
        header = payload[:VIDEO_HEADER_SIZE]
        data = payload[VIDEO_HEADER_SIZE:]

        packet_sequence = header[1]
        frame_id = header[2]
        flags = header[3]
        last_fragment = bool(flags & 0x01)

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
                self.last_camera_angle = (
                    self.last_camera_angle + (delta * 0.45)
                ) % 360.0

            filtered_angle = self.last_camera_angle
            camera_angle = self.relative_auto_rotate_angle(filtered_angle)
        else:
            filtered_angle = self.last_camera_angle
            camera_angle = self.relative_auto_rotate_angle(filtered_angle)

        if self.debug and (self.video_packet_count % 200 == 0):
            self.log(
                f"MOTION_PACKED: A={gyro_a} B={gyro_b} C={gyro_c} "
                f"raw={self.raw_camera_angle:.1f}° "
                f"filtered={self.last_camera_angle:.1f}° "
                f"relative={camera_angle:.1f}°"
                if camera_angle is not None
                else f"MOTION_PACKED: A={gyro_a} B={gyro_b} C={gyro_c} angle=?"
            )

        width = struct.unpack_from("<H", header, 12)[0]
        height = struct.unpack_from("<H", header, 14)[0]

        with self.jpeg_lock:
            soi = data.find(JPEG_SOI)

            if soi >= 0:
                if self.collecting_jpeg and self.jpeg_buffer:
                    self.dropped_frames += 1
                    self.dbg("JPEG: vorherigen unvollständigen Frame verworfen")

                self.jpeg_buffer.clear()
                self.jpeg_buffer.extend(data[soi:])
                self.collecting_jpeg = True
                self.current_frame_id = frame_id
                self.expected_packet_sequence = (packet_sequence + 1) & 0xFF
                self.current_width = width
                self.current_height = height
                self.current_camera_angle = camera_angle
                if self.debug and (
                    self.frame_count < 5
                    or self.frame_count % self.jpeg_log_every == 0
                ):
                    self.log(
                        f"JPEG START frame={frame_id} seq={packet_sequence} "
                        f"{width}x{height}"
                    )
            else:
                if not self.collecting_jpeg:
                    return

                if frame_id != self.current_frame_id:
                    self.dropped_frames += 1
                    self.dbg(
                        f"JPEG frame jump {self.current_frame_id}->{frame_id}; drop"
                    )
                    self.reset_jpeg_locked()
                    self.update_stats()
                    return

                if (
                    self.expected_packet_sequence is not None
                    and packet_sequence != self.expected_packet_sequence
                ):
                    missing = self.sequence_gap(
                        self.expected_packet_sequence, packet_sequence
                    )
                    self.log(
                        f"Paketverlust in Frame {frame_id}: erwartet "
                        f"{self.expected_packet_sequence}, erhalten {packet_sequence}; "
                        f"fehlend={missing}"
                    )
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
                self.log("JPEG > 5 MiB; Frame verworfen")
                self.reset_jpeg_locked()
                self.update_stats()
                return

            if not last_fragment:
                return

            jpeg = bytes(self.jpeg_buffer)
            completed_frame_id = self.current_frame_id
            completed_width = self.current_width
            completed_height = self.current_height
            completed_camera_angle = getattr(
                self, "current_camera_angle", None
            )
            self.reset_jpeg_locked()

        if not jpeg.startswith(JPEG_SOI):
            self.dropped_frames += 1
            self.update_stats()
            return

        eoi = jpeg.rfind(JPEG_EOI)
        if eoi < 0:
            self.dropped_frames += 1
            self.log(f"Frame {completed_frame_id}: LAST ohne JPEG EOI")
            self.update_stats()
            return

        jpeg = jpeg[:eoi + 2]
        self.emit_jpeg(
            jpeg,
            completed_frame_id,
            completed_width,
            completed_height,
            camera_angle=completed_camera_angle,
        )

    def reset_jpeg_locked(self):
        self.jpeg_buffer.clear()
        self.collecting_jpeg = False
        self.current_frame_id = None
        self.expected_packet_sequence = None
        self.current_width = 0
        self.current_height = 0

    @staticmethod
    def sequence_gap(expected, received):
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

    def send_nack(self, missing_sequences):
        missing = bytes(missing_sequences[:116])
        seq = self.next_sequence()
        packet = (
            struct.pack("<IHIH", MAGIC, seq, CMD_NACK, len(missing))
            + missing
        )
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(packet, (self.camera_ip, CAMERA_CONTROL_PORT))
            sock.close()
            self.nack_count += 1
            self.dbg(
                f"NACK #{self.nack_count}: protocol-seq={seq} "
                f"missing={list(missing)}"
            )
        except OSError as exc:
            self.dbg(f"NACK error: {exc}")

    # ------------------------------------------------------------------
    # Complete JPEG
    # ------------------------------------------------------------------

    def emit_jpeg(self, jpeg, frame_id, width, height, camera_angle=None):
        """Publish one complete JPEG.

        width/height are from the Soulear 16-byte transport header. The client
        separately parses the JPEG SOF marker because this camera advertises
        640x480 in the transport header while the actual JPEG is 480x480.
        """
        self.frame_count += 1
        self.last_jpeg = jpeg
        self.last_jpeg_angle = camera_angle

        transport_resolution = (int(width), int(height))
        self.last_transport_resolution = transport_resolution
        jpeg_width, jpeg_height = self.jpeg_dimensions(jpeg)
        if jpeg_width > 0 and jpeg_height > 0:
            jpeg_resolution = (jpeg_width, jpeg_height)
        else:
            jpeg_resolution = transport_resolution

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

        resolution_changed = (
            jpeg_resolution != self._last_logged_jpeg_resolution
        )
        if (
            self.frame_count <= 10
            or self.frame_count % self.jpeg_log_every == 0
            or resolution_changed
        ):
            self.log(
                f"JPEG #{self.frame_count}: frame={frame_id} "
                f"{len(jpeg):,} Bytes {resolution_text} "
                f"RX_FPS={self.fps_average:.1f}"
            )
            self._last_logged_jpeg_resolution = jpeg_resolution

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
                f"Recording – JPEG {jpeg_resolution[0]}×{jpeg_resolution[1]} "
                f"(Transport {transport_resolution[0]}×{transport_resolution[1]}) "
                f"– Frame {self.record_frame_count}"
            )
        else:
            if jpeg_resolution != transport_resolution:
                self.signals.status.emit(
                    f"Live – JPEG {jpeg_resolution[0]}×{jpeg_resolution[1]} "
                    f"(Transport {transport_resolution[0]}×{transport_resolution[1]})"
                )
            else:
                self.signals.status.emit(
                    f"Live – {jpeg_resolution[0]}×{jpeg_resolution[1]}"
                )

        self.update_stats()

    def update_stats(self):
        jpeg_res = (
            f"{self.last_jpeg_resolution[0]}×{self.last_jpeg_resolution[1]}"
            if self.last_jpeg_resolution
            else "?"
        )
        transport_res = (
            f"{self.last_transport_resolution[0]}×{self.last_transport_resolution[1]}"
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

    def watchdog_loop(self):
        # Give normal proOpenVideo time to answer and produce data.
        if not self.first_video_event.wait(1.0):
            if self.running and self.fallback_force:
                self.log(
                    "Normaler Open-Befehl lieferte nach 1 s keine Videopakete; "
                    "teste Force-Fallback 0x10016 einmalig."
                )
                self.open_video_force("no-video-fallback")

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
            self.log(
                f"STREAM STALL: seit {idle:.1f}s kein Video; "
                "sende normalen proOpenVideo erneut."
            )
            self.open_video_normal("watchdog")

    # ------------------------------------------------------------------
    # Save frame
    # ------------------------------------------------------------------

    def save_current_frame(self):
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
        self.signals.status.emit(
            f"Gespeichert: {os.path.abspath(filename)}{suffix}"
        )

    # ------------------------------------------------------------------
    # Start / stop
    # ------------------------------------------------------------------

    def start(self):
        if self.running:
            return
        self.running = True

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

            if online and self.status_payload is not None:
                if self.capabilities_byte & 0x10:
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

        except Exception as exc:
            self.log(f"START ERROR: {exc}")
            self.signals.status.emit(f"Startfehler: {exc}")
            self.stop()

    def stop(self):
        if self.camera_recording or self.record_ffmpeg is not None:
            try:
                self.stop_video_recording()
            except Exception as exc:
                self.log(f"RECORD_STOP beim Beenden fehlgeschlagen: {exc}")

        if not self.running:
            return
        self.running = False
        self.log("Stopping Soulear...")

        for sock in (
            self.video_socket,
            self.video2_socket,
            self.presence_video_socket,
            self.presence_control1_socket,
            self.presence_control2_socket,
        ):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

        if self.dumpcap_process is not None:
            try:
                self.dumpcap_process.terminate()
                self.dumpcap_process.wait(timeout=1.5)
            except Exception:
                try:
                    self.dumpcap_process.kill()
                except Exception:
                    pass
            self.dumpcap_process = None

        self.log("Soulear stopped.")


# ======================================================================
# GUI
# ======================================================================

class MainWindow(QMainWindow):
    def __init__(self, args):
        super().__init__()
        self.setWindowTitle("Soulear Linux Camera")
        self.resize(800, 700)
        self.current_pixmap = None

        self.image_label = QLabel("Warte auf Soulear …")
        self.image_label.setAlignment(Qt.AlignCenter)
        self.image_label.setMinimumSize(640, 480)

        self.status_label = QLabel("Initialisiere …")
        self.status_label.setAlignment(Qt.AlignCenter)

        self.stats_label = QLabel("Frames: 0")
        self.stats_label.setAlignment(Qt.AlignCenter)

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

        self.offset_slider = QSlider(Qt.Orientation.Vertical)
        self.offset_slider.setRange(-180, 180)
        self.offset_slider.setEnabled(self.auto_rotate_button.isChecked())

        self.nocrop_button = QPushButton("■")
        self.nocrop_button.setCheckable(True)
        self.nocrop_button.setChecked(False)
        self.nocrop_button.setEnabled(self.auto_rotate_button.isChecked())

        self.flip_button = QPushButton("↔")
        self.flip_button.setCheckable(True)
        self.flip_button.setChecked(False)

        slider_layout = QVBoxLayout()
        slider_layout.addWidget(self.offset_slider, stretch=1)
        slider_layout.addWidget(self.nocrop_button)
        slider_layout.addWidget(self.flip_button)

        image_layout = QHBoxLayout()
        image_layout.addLayout(slider_layout)
        image_layout.addWidget(self.image_label, stretch=1)

        layout = QVBoxLayout()
        layout.addLayout(image_layout, stretch=1)
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
            debug=args.debug,
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
        self.preview_timer.setTimerType(Qt.PreciseTimer)
        self.preview_timer.setInterval(50)  # 20 Hz
        self.preview_timer.timeout.connect(self.display_recording_style_frame)
        self.preview_timer.start()

        threading.Thread(target=self.camera.start, daemon=True).start()

    def start_recording(self):
        self.record_start_button.setEnabled(False)
        self.record_stop_button.setEnabled(True)
        self.auto_rotate_button.setEnabled(False)
        self.status_label.setText("Starte Kamera-Recording …")

        def worker():
            ok = self.camera.start_video_recording()
            if ok:
                self.signals.recording_state.emit(True)
                mode = "auto-rotiert" if self.camera.record_auto_rotate else "original"
                self.signals.status.emit(
                    f"Videoaufnahme gestartet – {mode}; Auto-Rotation bis zum Stop gesperrt"
                )
            else:
                self.signals.status.emit("Lokale Videoaufnahme konnte nicht gestartet werden")
                self.signals.recording_state.emit(False)

        threading.Thread(target=worker, daemon=True).start()

    def stop_recording(self):
        self.record_stop_button.setEnabled(False)
        self.status_label.setText("Stoppe Kamera-Recording …")

        def worker():
            self.camera.stop_video_recording()
            self.signals.status.emit("Recording beendet")
            self.signals.recording_state.emit(False)

        threading.Thread(target=worker, daemon=True).start()

    def set_recording_ui_state(self, active):
        active = bool(active)
        self.record_start_button.setEnabled(not active)
        self.record_stop_button.setEnabled(active)
        self.auto_rotate_button.setEnabled(not active)

    def set_led(self, enabled):
        self.led_on_button.setEnabled(False)
        self.led_off_button.setEnabled(False)

        def worker():
            ok = self.camera.set_led(enabled)
            if ok:
                self.signals.status.emit(
                    "LED eingeschaltet" if enabled else "LED ausgeschaltet"
                )
            else:
                self.signals.status.emit("LED-Befehl fehlgeschlagen")
            self.led_on_button.setEnabled(True)
            self.led_off_button.setEnabled(True)

        threading.Thread(target=worker, daemon=True).start()

    def set_auto_rotate(self, enabled):
        if self.camera.camera_recording:
            # The recording pipeline freezes its orientation mode at start.
            # Reject programmatic/user changes while the file is open too.
            self.auto_rotate_button.blockSignals(True)
            self.auto_rotate_button.setChecked(self.camera.auto_rotate)
            self.auto_rotate_button.blockSignals(False)
            self.signals.status.emit(
                "Auto-Rotation kann während einer Videoaufnahme nicht geändert werden"
            )
            return

        self.camera.auto_rotate = bool(enabled)
        self.offset_slider.setEnabled(bool(enabled))
        self.nocrop_button.setEnabled(bool(enabled))
        if enabled:
            self.camera.auto_rotate_zero = self.camera.last_camera_angle
        else:
            self.camera.auto_rotate_zero = None

        self.auto_rotate_button.setText(
            "Auto-Rotation: AN" if enabled else "Auto-Rotation: AUS"
        )
        angle = self.camera.last_camera_angle
        if enabled:
            self.signals.status.emit(
                "Auto-Rotation aktiviert – gepackter Soulear-Sensorwinkel"
                + (f" – Winkel {angle}°" if angle is not None else "")
            )
        else:
            self.signals.status.emit("Auto-Rotation deaktiviert")

    def display_recording_style_frame(self):
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
                self.camera.log(
                    f"PREVIEW20: Start mit {len(q)} gepufferten Frames"
                )

            # A receive burst can briefly outrun the 20-Hz player. Keep only a
            # few recent frames so the preview never drifts seconds behind.
            if len(q) > self.camera.gui_preview_max_latency_frames:
                target = self.camera.gui_preview_target_buffer
                dropped = 0
                while len(q) > target:
                    q.popleft()
                    dropped += 1
                self.camera.dbg(
                    f"PREVIEW20: {dropped} alte Frames verworfen "
                    f"(Latenzbegrenzung)"
                )

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

    def display_frame(self, jpeg, camera_angle=None):
        image = QImage.fromData(jpeg, "JPEG")
        if image.isNull():
            print("Qt konnte JPEG nicht dekodieren", flush=True)
            return

        pixmap = QPixmap.fromImage(image.mirrored(self.flip_button.isChecked(), False))

        if (
            self.camera.auto_rotate
            and camera_angle is not None
        ):
            #  show only the centered circular region that is guaranteed
            # to exist for every rotation.  Render into a FIXED square canvas
            # so the visible circle never changes size at 0/45/90 degrees.
            if self.nocrop_button.isChecked():
                side = 2**0.5 * max(pixmap.width(), pixmap.height())
            else:
                side = min(pixmap.width(), pixmap.height())

            rotated = QPixmap(side, side)
            rotated.fill(Qt.transparent)

            painter = QPainter(rotated)
            painter.setRenderHint(QPainter.SmoothPixmapTransform, True)

            clip = QPainterPath()
            clip.addEllipse(QRectF(0.0, 0.0, float(side), float(side)))
            painter.setClipPath(clip)

            painter.translate(side / 2.0, side / 2.0)
            painter.rotate(-float(camera_angle) + self.offset_slider.value())
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

    def update_scaled_pixmap(self):
        if self.current_pixmap is None:
            return
        self.image_label.setPixmap(
            self.current_pixmap.scaled(
                self.image_label.size(),
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation,
            )
        )

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.update_scaled_pixmap()

    def closeEvent(self, event):
        self.camera.stop()
        event.accept()


# ======================================================================
# Main
# ======================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Linux client for Soulear/YPC Wi-Fi inspection cameras"
    )
    parser.add_argument(
        "--dumpcap",
        action="store_true",
        help="Use optional dumpcap packet capture instead of normal UDP sockets",
    )
    parser.add_argument(
        "--interface", "-i",
        default=None,
        help="Interface for --dumpcap. If omitted, it is detected via the route "
             "to --camera-ip",
    )
    parser.add_argument(
        "--local-ip",
        default="192.168.1.10",
        help="Local IPv4 address used for UDP sockets "
             "(default: 192.168.1.10)",
    )
    parser.add_argument(
        "--camera-ip", "--camera",
        dest="camera_ip",
        default="192.168.1.1",
        help="Camera IPv4 address (default: 192.168.1.1)",
    )
    parser.add_argument(
        "--broadcast-ip", "--broadcast",
        dest="broadcast_ip",
        default="192.168.1.255",
        help="Broadcast IPv4 address used by presence keepalives "
             "(default: 192.168.1.255)",
    )
    parser.add_argument("--debug", action="store_true",
                        help="Enable verbose protocol logging")
    parser.add_argument("--no-keepalive", action="store_true",
                        help="Disable legacy presence keepalives")
    parser.add_argument("--no-online-monitor", action="store_true",
                        help="Disable periodic CHECK_ONLINE")
    parser.add_argument("--no-force-fallback", action="store_true",
                        help="Disable OPEN_VIDEO_FORCE fallback")
    parser.add_argument("--no-auto-reopen", action="store_true",
                        help="Disable stream watchdog reopen")
    args = parser.parse_args()

    app = QApplication(sys.argv)
    window = MainWindow(args)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
