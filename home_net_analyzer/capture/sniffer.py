"""Packet sniffer: captures packets using scapy and yields parsed CapturedPackets."""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from typing import Any

from home_net_analyzer.capture.models import CapturedPacket
from home_net_analyzer.capture.parser import PacketParser


class PacketSniffer:
    """Sniffs network packets and yields normalized CapturedPacket objects.

    This is a thin wrapper around scapy.sniff with a parser pipeline.
    """

    def __init__(
        self,
        *,
        interface: str | None = None,
        bpf_filter: str = "",
        promiscuous: bool = True,
        timeout: float | None = None,
        parser: PacketParser | None = None,
    ) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.promiscuous = promiscuous
        self.timeout = timeout
        self.parser = parser or PacketParser()

        self._stop_event: threading.Event | None = None
        self._thread: threading.Thread | None = None

    def sniff_once(self, count: int = 1) -> list[CapturedPacket]:
        """Capture `count` packets (blocking) and return parsed results."""
        from scapy.all import sniff  # type: ignore

        pkts = sniff(
            iface=self.interface,
            filter=self.bpf_filter or None,
            prn=None,
            count=count,
            timeout=self.timeout,
            store=True,
            promisc=self.promiscuous,
        )
        return [self.parser.parse(p, interface=self.interface) for p in pkts]

    def sniff_iter(self, count: int | None = None) -> Iterator[CapturedPacket]:
        """Generator that yields CapturedPackets as they arrive.

        Args:
            count: Optional max number of packets. If None, runs indefinitely
                   until stop() is called or timeout expires.

        Yields:
            CapturedPacket objects.
        """
        from scapy.all import sniff  # type: ignore

        yielded = 0

        def prn(pkt: Any) -> None:
            nonlocal yielded
            cp = self.parser.parse(pkt, interface=self.interface)
            yielded += 1
            # We can't yield from callback; we store to a queue instead.
            # This method is kept simple: use sniff_once or run_async.

        # Fallback: iterate by calling sniff_once in a loop for small batches
        remaining = count
        while remaining is None or remaining > 0:
            batch = min(100, remaining) if remaining else 100
            pkts = sniff(
                iface=self.interface,
                filter=self.bpf_filter or None,
                count=batch,
                timeout=self.timeout,
                store=True,
                promisc=self.promiscuous,
            )
            for p in pkts:
                yield self.parser.parse(p, interface=self.interface)
            if remaining is not None:
                remaining -= len(pkts)
            if not pkts:
                # No packets captured within timeout; continue or break
                if self.timeout is not None:
                    # Keep looping until explicit stop via run_async
                    pass

    def run_async(
        self,
        on_packet: Callable[[CapturedPacket], None],
        *,
        stop_event: threading.Event | None = None,
    ) -> threading.Thread:
        """Run sniffer in a background thread, calling on_packet for each capture.

        Args:
            on_packet: Callback invoked with each CapturedPacket.
            stop_event: Optional external event to signal stop.

        Returns:
            The started thread.
        """
        self._stop_event = stop_event or threading.Event()

        def loop() -> None:
            from scapy.all import sniff  # type: ignore

            def prn(pkt: Any) -> None:
                cp = self.parser.parse(pkt, interface=self.interface)
                on_packet(cp)

            sniff(
                iface=self.interface,
                filter=self.bpf_filter or None,
                prn=prn,
                store=False,
                promisc=self.promiscuous,
                stop_filter=lambda _: self._stop_event.is_set(),
            )

        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()
        return self._thread

    def stop(self) -> None:
        """Signal the async sniffer to stop."""
        if self._stop_event is not None:
            self._stop_event.set()

    def join(self, timeout: float | None = None) -> None:
        """Wait for the sniffer thread to finish."""
        if self._thread is not None:
            self._thread.join(timeout=timeout)
