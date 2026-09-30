# Does the quickfix in this interpreter reject a certificate issued for the wrong name?
#
# Mints a throwaway CA and two leaf certificates -- one for the name we dial, one for another
# name -- runs a TLS listener on loopback behind each, points an SSLSocketInitiator at it, and
# reports what the listener saw. Nothing leaves the machine and no real venue is involved.
#
# Exit 0: the matching leaf completes a handshake and receives the Logon, the mismatched leaf is
# refused before any bytes arrive. Exit 1: the name check is absent (the upstream PyPI build
# completes both handshakes and sends the Logon to either). Exit 2: the openssl CLI is missing.
import pathlib
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading

try:
    import quickfix as fix
except ImportError as error:
    print(f"quickfix does not import in this interpreter ({sys.executable}): {error}")
    sys.exit(1)

# Resolves to 127.0.0.1 without touching DNS, and is a name, so the check has something to compare.
CONNECT_HOST = "localhost"
MISMATCHED_NAME = "not-the-venue.invalid"
# How long the listener waits for the engine to connect and speak.
LISTEN_TIMEOUT_SECONDS = 6
READ_TIMEOUT_SECONDS = 3
EXIT_TOOLING_MISSING = 2

SETTINGS = """[DEFAULT]
ConnectionType=initiator
StartTime=00:00:00
EndTime=00:00:00
UseDataDictionary=N
ReconnectInterval=1
SSLProtocol=-all +TLSv1_2 +TLSv1_3
CertificateVerifyLevel=1
CertificationAuthoritiesFile={ca}

[SESSION]
BeginString=FIX.4.4
SenderCompID=PROBE
TargetCompID=FAKE
SocketConnectHost={host}
SocketConnectPort={port}
HeartBtInt=30
"""


class NullApplication(fix.Application):
    """The minimum quickfix accepts; the session never gets past the handshake."""

    def onCreate(self, sessionID): pass
    def onLogon(self, sessionID): pass
    def onLogout(self, sessionID): pass
    def toAdmin(self, message, sessionID): pass
    def fromAdmin(self, message, sessionID): pass
    def toApp(self, message, sessionID): pass
    def fromApp(self, message, sessionID): pass


def openssl(*arguments) -> None:
    subprocess.run(["openssl", *arguments], check=True, capture_output=True)


def mint_certificates(directory: pathlib.Path) -> tuple[pathlib.Path, dict]:
    """
    :return: The CA certificate path, and {label: (leaf certificate, leaf key)} for both leaves.
    """
    ca_key, ca = directory / "ca.key", directory / "ca.pem"
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", ca_key, "-out", ca,
            "-days", "1", "-subj", "/CN=throwaway-ca")
    leaves = {}
    for label, name in (("matching", CONNECT_HOST), ("mismatched", MISMATCHED_NAME)):
        key, request, certificate = (directory / f"{label}.{suffix}" for suffix in ("key", "csr", "pem"))
        extensions = directory / f"{label}.ext"
        extensions.write_text(f"subjectAltName=DNS:{name}\n")
        openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", request, "-subj", f"/CN={name}")
        openssl("x509", "-req", "-in", request, "-CA", ca, "-CAkey", ca_key, "-CAcreateserial",
                "-out", certificate, "-days", "1", "-extfile", extensions)
        leaves[label] = (certificate, key)
    return ca, leaves


class FakeVenue(threading.Thread):
    """A certificate with a socket behind it: records whether the handshake completed and what followed."""

    def __init__(self, certificate: pathlib.Path, key: pathlib.Path):
        super().__init__(daemon=True)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certificate, key)
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(LISTEN_TIMEOUT_SECONDS)
        self.port = self.listener.getsockname()[1]
        self.handshake = "no connection"
        self.bytes_received = 0
        self.finished = threading.Event()

    def run(self):
        try:
            raw, _ = self.listener.accept()
        except OSError:
            self.finished.set()
            return
        raw.settimeout(READ_TIMEOUT_SECONDS)
        try:
            with self.context.wrap_socket(raw, server_side=True) as tls:
                self.handshake = "completed"
                try:
                    self.bytes_received = len(tls.recv(4096))
                except OSError:
                    pass
        except ssl.SSLError as error:
            self.handshake = f"refused ({error.reason})"
        except OSError as error:
            self.handshake = f"refused ({error})"
        finally:
            self.listener.close()
            self.finished.set()


def connect_once(ca: pathlib.Path, certificate: pathlib.Path, key: pathlib.Path, directory: pathlib.Path,
                 label: str) -> tuple[str, int]:
    """
    :return: What the fake venue saw: the handshake outcome, and bytes received after it.
    """
    venue = FakeVenue(certificate, key)
    venue.start()
    settings = directory / f"{label}.cfg"
    settings.write_text(SETTINGS.format(ca=ca, host=CONNECT_HOST, port=venue.port))
    application, store = NullApplication(), fix.MemoryStoreFactory()
    initiator = fix.SSLSocketInitiator(application, store, fix.SessionSettings(str(settings)))
    initiator.start()
    venue.finished.wait(LISTEN_TIMEOUT_SECONDS + READ_TIMEOUT_SECONDS)
    initiator.stop()
    return venue.handshake, venue.bytes_received


def judge(matching: tuple[str, int], mismatched: tuple[str, int]) -> tuple[bool, str]:
    """
    The verdict, from what the two fake venues observed.

    The matching leaf is the positive control: without it, an engine that rejected every
    certificate -- wrong CA file, wrong protocol -- would pass.
    :param matching: (handshake outcome, bytes received) with the leaf for the dialled name.
    :param mismatched: The same with the leaf for another name.
    :return: (name check present, one-line reason).
    """
    if matching[0] != "completed" or matching[1] == 0:
        return False, "the matching certificate was not accepted, so nothing here proves a name check"
    if mismatched[0] == "completed":
        return False, "the mismatched certificate was accepted" + (
            " and the Logon was sent to it" if mismatched[1] else "")
    return True, "the mismatched certificate was refused before any FIX message was sent"


def main() -> int:
    if shutil.which("openssl") is None:
        print("openssl CLI not found on PATH; it mints the throwaway certificates")
        return EXIT_TOOLING_MISSING
    print(f"quickfix from {fix.__file__}")
    with tempfile.TemporaryDirectory(prefix="quickfix-hostname-check-") as name:
        directory = pathlib.Path(name)
        ca, leaves = mint_certificates(directory)
        observed = {label: connect_once(ca, *leaves[label], directory, label) for label in ("matching", "mismatched")}
    print(f"\n{'leaf':<12}{'handshake':<40}bytes received after it")
    for label, (handshake, received) in observed.items():
        print(f"{label:<12}{handshake:<40}{received}")
    present, reason = judge(observed["matching"], observed["mismatched"])
    print(f"\nHOSTNAME CHECK {'PRESENT' if present else 'ABSENT'}: {reason}")
    return 0 if present else 1


if __name__ == "__main__":
    sys.exit(main())
