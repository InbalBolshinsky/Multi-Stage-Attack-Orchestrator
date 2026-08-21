from __future__ import annotations

import socket
import subprocess
import time
from pathlib import Path

import pytest

from orchestrator import AttackSelector
from orchestrator.attacks import all_attacks

SIMULATOR_BIN = Path(__file__).resolve().parent.parent / "simulator" / "simulator"


@pytest.fixture
def selector() -> AttackSelector:
    """Fresh selector with all four example attacks registered."""
    return AttackSelector(all_attacks())


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class SimulatorHandle:
    """Wraps a running simulator subprocess and the port it's listening on."""

    def __init__(self, process: subprocess.Popen, port: int) -> None:
        self.process = process
        self.port = port

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)


def _wait_for_port(port: int, timeout: float = 2.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.02)
    raise TimeoutError(f"simulator never opened port {port}")


@pytest.fixture
def spawn_simulator(tmp_path):
    """
    Call spawn_simulator(**cli_flags) to start a real simulator process
    and get back a SimulatorHandle once it's ready. Used by tests that
    need a real connection instead of the in-memory fake.
    """
    if not SIMULATOR_BIN.exists():
        pytest.skip(f"simulator binary not built at {SIMULATOR_BIN} (run `make` in simulator/)")

    handles: list[SimulatorHandle] = []

    def _spawn(
        model: str = "iPhone8,1",
        ios: str = "14.4",
        battery: int = 60,
        fail_stages: list[int] | None = None,
        drop_stage: int | None = None,
        crash_stage: int | None = None,
        bfu: bool = False,
        jailbroken: bool = False,
    ) -> SimulatorHandle:
        port = _free_port()
        args = [str(SIMULATOR_BIN), "--port", str(port), "--model", model, "--ios", ios, "--battery", str(battery)]
        for stage_id in fail_stages or []:
            args += ["--fail-stage", str(stage_id)]
        if drop_stage is not None:
            args += ["--drop-stage", str(drop_stage)]
        if crash_stage is not None:
            args += ["--crash-stage", str(crash_stage)]
        if bfu:
            args += ["--bfu"]
        if jailbroken:
            args += ["--jailbroken"]

        log_path = tmp_path / f"sim-{port}.log"
        proc = subprocess.Popen(args, stdout=open(log_path, "w"), stderr=subprocess.STDOUT)
        _wait_for_port(port)
        handle = SimulatorHandle(proc, port)
        handles.append(handle)
        return handle

    yield _spawn

    for h in handles:
        h.stop()
