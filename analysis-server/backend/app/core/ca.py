import os
from pathlib import Path
from datetime import datetime, timezone, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

_PROJECT_ROOT = Path(__file__).resolve().parents[4]


def _resolve_path(env_var: str, default_relative: str) -> Path:
    raw = os.getenv(env_var, "")
    if raw:
        p = Path(raw)
        return p if p.is_absolute() else _PROJECT_ROOT / p
    return _PROJECT_ROOT / default_relative


def _get_ca_key_path() -> Path:
    return _resolve_path("CA_KEY_PATH", "certs/ca.key.pem")


def _get_ca_cert_path() -> Path:
    return _resolve_path("CA_CERT_PATH", "certs/ca.cert.pem")


def init_ca() -> None:
    """서버 시작 시 CA 키와 자체 서명 인증서가 없으면 생성한다."""
    key_path = _get_ca_key_path()
    cert_path = _get_ca_cert_path()

    if key_path.exists() and cert_path.exists():
        print(f"[CA] 이미 초기화됨: {key_path}")
        return

    key_path.parent.mkdir(parents=True, exist_ok=True)

    print("[CA] CA 키 및 인증서 생성 중...")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "KR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "K9 Security"),
        x509.NameAttribute(NameOID.COMMON_NAME, "K9 Enrollment CA"),
    ])

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365 * 10))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )

    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[CA] 생성 완료: {key_path}, {cert_path}")


def get_ca_key() -> rsa.RSAPrivateKey:
    key_path = _get_ca_key_path()
    if not key_path.exists():
        raise RuntimeError("CA_NOT_INITIALIZED: CA 키 파일이 없습니다. 서버를 재시작하세요.")
    return serialization.load_pem_private_key(key_path.read_bytes(), password=None)


def get_ca_cert() -> x509.Certificate:
    cert_path = _get_ca_cert_path()
    if not cert_path.exists():
        raise RuntimeError("CA_NOT_INITIALIZED: CA 인증서 파일이 없습니다. 서버를 재시작하세요.")
    return x509.load_pem_x509_certificate(cert_path.read_bytes())


def sign_csr(csr_pem: str) -> str:
    """PEM 인코딩된 CSR을 서버 CA로 서명하여 PEM 인증서 문자열을 반환한다."""
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
    except Exception as e:
        raise ValueError(f"CSR 파싱 실패: {e}") from e

    if not csr.is_signature_valid:
        raise ValueError("CSR 서명이 유효하지 않습니다.")

    ca_key = get_ca_key()
    ca_cert = get_ca_cert()

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    return cert.public_bytes(serialization.Encoding.PEM).decode()
