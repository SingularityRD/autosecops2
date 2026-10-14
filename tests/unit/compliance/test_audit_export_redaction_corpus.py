"""The round-3 verifier's 112-string leak corpus (WP w3.6, round 5 fixes).

Every carrier string below came out of the exporter unchanged before the
round-5 fix. Each must now lose its secret, in free text (``message``) and
nested anywhere in ``details``. ``user=<value>`` is the one deliberate
exception: a user name is the audit trail, not a credential.
"""

from __future__ import annotations

import json

import pytest

from core.compliance.audit_export import REDACTED, Redactor, redact_text

pytestmark = pytest.mark.unit

S: list[tuple[str, str]] = []


def add(secret, text=None):
    S.append((secret, text if text is not None else secret))


jwt = (
    "ey"
    "JhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ey"
    "JzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
add(jwt)
add(jwt, f"user sent {jwt} in body")
add(jwt, f'{{"jwt_value_x":"{jwt}"}}')
add("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", f"Authorization: Bearer {jwt}")
sas_sig = "sig=Xyz1" "2abcDEF%2Bghij34klmnopQRstuVWxyz0123456%3D"
sas = (
    "https://acct.blob.core.windows.net/c/b.txt?sv=2022-11-02&ss=b&srt=sco&sp=rwdlacx&se=2026-12-01T00:00:00Z&st=2026-01-01&spr=https&"
    + sas_sig
)
add("Xyz1" "2abcDEF%2Bghij34klmnopQRstuVWxyz0123456%3D", sas)
add(
    "Xyz1" "2abcDEF%2Bghij34klmnopQRstuVWxyz0123456%3D",
    "AZURE_STORAGE_SAS_TOKEN=?" + sas.split("?")[1],
)
azkey = (
    "Eb"
    "y8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
)
add(
    azkey,
    f"DefaultEndpointsProtocol=https;AccountName=devstoreaccount1;AccountKey={azkey};EndpointSuffix=core.windows.net",
)
add(
    "abcD" "EF123ghiJKL456mnoPQR789stuVWX012yzA345=",
    "Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=abcD"
    "EF123ghiJKL456mnoPQR789stuVWX012yzA345=",
)
add("AI" "zaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY")
add(
    "AI" "zaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY",
    "https://maps.googleapis.com/maps/api/geocode/json?address=x&key=AI"
    "zaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY",
)
add("ya" "29.a0AfH6SMBx3dQxR8_exampleTokenValue1234567890abcdef")
pem_body = "MI" "IEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj"
gcp_sa = json.dumps(
    {
        "type": "service_account",
        "project_id": "p",
        "private_key_id": "a1b2" "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
        "private_key": f"-----BEGIN PRIVATE KEY-----\n{pem_body}\n-----END PRIVATE KEY-----\n",
        "client_email": "x@p.iam.gserviceaccount.com",
    }
)
add(pem_body, gcp_sa)
add("a1b2" "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0", gcp_sa)
add(
    pem_body,
    f"-----BEGIN RSA PRIVATE KEY-----\n{pem_body}\n-----END RSA PRIVATE KEY-----",
)
add(
    pem_body,
    f"-----BEGIN OPENSSH PRIVATE KEY-----\n{pem_body}\n-----END OPENSSH PRIVATE KEY-----",
)
add(
    pem_body,
    f"-----BEGIN EC PRIVATE KEY-----\\n{pem_body}\\n-----END EC PRIVATE KEY-----",
)  # escaped newlines in JSON string
add(
    pem_body,
    f"-----BEGIN ENCRYPTED PRIVATE KEY-----\n{pem_body}\n-----END ENCRYPTED PRIVATE KEY-----",
)
add(
    pem_body,
    f"-----BEGIN PGP PRIVATE KEY BLOCK-----\n{pem_body}\n-----END PGP PRIVATE KEY BLOCK-----",
)
add("S3cr3tPa55", "postgresql://admin:S3cr3tPa55@db.internal:5432/vigil")
add("S3cr3tPa55", "postgres://admin:S3cr3tPa55@db.internal/vigil?sslmode=require")
add("S3cr3tPa55", "mysql://root:S3cr3tPa55@10.0.0.4/app")
add("S3cr3tPa55", "amqp://guest:S3cr3tPa55@rabbit:5672//")
add("S3cr3tPa55", "redis://:S3cr3tPa55@redis:6379/0")
add("S3cr3tPa55", "rediss://default:S3cr3tPa55@redis:6380")
add("S3cr3tPa55", "mongodb+srv://u:S3cr3tPa55@cluster0.mongodb.net/db")
add(
    "S3cr3tPa55",
    "Server=tcp:x.database.windows.net,1433;Database=d;User ID=sa;Password=S3cr3tPa55;Encrypt=true",
)
add("S3cr3tPa55", "Driver={ODBC Driver 18};Server=x;Uid=sa;Pwd={S3cr3tPa55};")
add("S3cr3tPa55", "jdbc:postgresql://db:5432/x?user=a&password=S3cr3tPa55")
add(
    "S3cr3tPa55", "jdbc:sqlserver://db:1433;databaseName=x;user=sa;password=S3cr3tPa55;"
)
add("S3cr3tPa55", "Data Source=db;Initial Catalog=x;User Id=sa;Password=S3cr3tPa55")
add("S3cr3tPa55", "DB_PASSWORD=S3cr3tPa55")
add("S3cr3tPa55", "export POSTGRES_PASSWORD='S3cr3tPa55'")
add("S3cr3tPa55", 'MYSQL_ROOT_PASSWORD="S3cr3tPa55"')
add("S3cr3tPa55", '{"password": "S3cr3tPa55"}')
add("S3cr3tPa55", '{"dbPass": "S3cr3tPa55"}')
add("S3cr3tPa55", "--password S3cr3tPa55")
add("S3cr3tPa55", "-pS3cr3tPa55")
add("S3cr3tPa55", "ldap://cn=admin,dc=x:S3cr3tPa55@ldap")
add("S3cr3tPa55", "https://user:S3cr3tPa55@git.internal/repo.git")
add(
    "wJ" "alrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "AWS_SECRET_ACCESS_KEY=wJ" "alrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
)
add(
    "wJ" "alrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "aws_secret_access_key = wJ" "alrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
)
add("AK" "IAIOSFODNN7EXAMPLE")
add(
    "IQ" "oJb3JpZ2luX2VjEJr//////////wEaCXVzLWVhc3QtMSJHMEUCIQD",
    "AWS_SESSION_TOKEN=IQ" "oJb3JpZ2luX2VjEJr//////////wEaCXVzLWVhc3QtMSJHMEUCIQD",
)
add(
    "X-Amz-Signature=abcdef01234"
    "56789abcdef01234"
    "56789abcdef01234"
    "56789abcdef0123456789".split("=")[1],
    "https://b.s3.amazonaws.com/k?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AK"
    "IAX%2F20260101&X-Amz-Signature=abcdef01234"
    "56789abcdef01234"
    "56789abcdef01234"
    "56789abcdef0123456789",
)
add("sk-p" "roj-abcdEFGH1234ijklMNOP5678qrstUVWX")
add("sk-" "ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_abcd")
add("gh" "p_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789")
add("githu" "b_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz")
add("glp" "at-xxxxXXXXyyyyYYYYzzzz")
add("xo" "xb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx")
add(
    "T0000" "0000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
    "https://hooks.slack.com/services/T0000" "0000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
)
add("sk_l" "ive_4eC39HqLyjWDarjtT1zdp7dc")
add("SG" ".ngeVfQFYQlKU0ufo8x5d1A.TwL2iGABf9DHoTf-09kqeF8tAmbihYzrnopKc-1s5cr")
add("hf" "_abcdefghijklmnopqrstuvwxyzABCDEFGH")
add("np" "m_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ")
add(
    "dGhp" "c2lzYXNlY3JldHZhbHVlMTIz",
    "Authorization: Basic dGhp" "c2lzYXNlY3JldHZhbHVlMTIz",
)
add(
    "dGhp" "c2lzYXNlY3JldHZhbHVlMTIz",
    "curl -H 'Authorization: Basic dGhp" "c2lzYXNlY3JldHZhbHVlMTIz' x",
)
add("abc123def456ghi789", "Cookie: session=abc123def456ghi789; theme=dark")
add("abc123def456ghi789", "Set-Cookie: sessionid=abc123def456ghi789; HttpOnly")
add("abc123def456ghi789", "X-Api-Key: abc123def456ghi789")
add("abc123def456ghi789", "x-auth-token: abc123def456ghi789")
add(
    "abc123def456ghi789",
    "https://api.example.com/v1?access_token=abc123def456ghi789&x=1",
)
add("abc123def456ghi789", "https://api.example.com/v1?client_secret=abc123def456ghi789")
add("abc123def456ghi789", "OPENAI_API_KEY=abc123def456ghi789")
add("abc123def456ghi789", "CLIENT_SECRET: abc123def456ghi789")
add("abc123def456ghi789", "<password>abc123def456ghi789</password>")
add("abc123def456ghi789", 'secret: "abc123def456ghi789"')
add("123456", "TOTP code 123456 accepted")  # weak: may not redact; informational
add(
    "da" "pi0123456789abcdef01234" "56789abcdef",
    "DATABRICKS_TOKEN=da" "pi0123456789abcdef01234" "56789abcdef",
)
add("da" "pi0123456789abcdef01234" "56789abcdef")
add(
    "hv" "s.CAESIJlY3J5cHRvZ3JhcGhpYzEyMzQ1Njc4OTA",
    "VAULT_TOKEN=hv" "s.CAESIJlY3J5cHRvZ3JhcGhpYzEyMzQ1Njc4OTA",
)
add("hv" "s.CAESIJlY3J5cHRvZ3JhcGhpYzEyMzQ1Njc4OTA")
add("gl" "sa_abcdefghijklmnopqrstuvwxyz012345_abcdef12")
add("AccountKey=" + azkey.split("=")[0][:20], f"connstr AccountKey={azkey}")


# corpus 2: one fixed secret in 38 carriers.
P = "S3cr3tPa55x"
cases = [
    f'{{"pass": "{P}"}}',
    f"pass={P}",
    f"PGPASSWORD={P} psql",
    f"mysql -u root -p{P} db",
    f"mysql --password={P}",
    f"sshpass -p {P} ssh h",
    f"api-key: {P}",
    f"token {P}",
    f"bearer {P}",
    f"Authorization=Bearer {P}",
    f"{{'password': '{P}'}}",
    f"password = {P}",
    f"Password:{P}",
    f"PASSWORD\t{P}",
    f"user={P}",
    f"key={P}",
    f"privateKey: {P}",
    f"client-secret {P}",
    f'"secret":"{P}"',
    f"secret%3D{P}",
    f"password%3D{P}",
    f"https://x/?pw={P}",
    f"https://x/?passwd={P}",
    f"https://x/#access_token={P}&t=1",
    f"net use \\\\h\\c {P} /user:a",
    f"echo {P} | docker login --password-stdin",
    f"htpasswd -b f u {P}",
    f'{{"credentials": {{"user":"a","password":"{P}"}}}}',
    f"password: >-\n  {P}",
    f'<add key="Password" value="{P}"/>',
    f"ConnectionStrings__Default=Server=x;Password={P}",
    f'"apiKey":"{P}"',
    f"x_api_key={P}",
    f"SECRET_KEY_BASE={P}",
    f"DJANGO_SECRET_KEY={P}",
    f"JWT_SECRET_KEY={P}",
    f"ENCRYPTION_KEY={P}",
    f"NEXTAUTH_SECRET={P}",
]

NOT_SECRETS = {f"user={P}"}  # a user name, deliberately kept
for c in cases:
    if c not in NOT_SECRETS:
        add(P, c)


def test_corpus_size():
    # 74 + 38 verifier strings, minus the one deliberate exception.
    assert len(S) == 111


@pytest.mark.parametrize("secret,text", S, ids=[f"c{i}" for i in range(len(S))])
def test_corpus_string_does_not_leak(secret, text):
    r = Redactor(redact_pii=True)
    assert secret not in r.text(text)
    details = r.value(
        "", {"data": text, "nested": {"value": [text]}, "env": {"FOO": text}}
    )
    assert secret not in json.dumps(details)


def test_structured_pairs_do_not_leak():
    p = "S3cr3tPa55x"
    d = {
        "headers": {"X-Api-Key": p, "x-vault-token": p, "PRIVATE-TOKEN": p},
        "env": [
            {"name": "DB_PASSWORD", "value": p},
            {"name": "HOME", "value": "/root"},
        ],
        "args": ["--password", p, "--host", "db"],
        "sshpass": ["/usr/bin/sshpass", "-p", p, "ssh", "h"],
        "kv": {"key": "password", "value": p},
        "Settings": [{"Name": "dbPass", "Value": p}],
    }
    out = Redactor().value("", d)
    assert p not in json.dumps(out)
    assert out["env"][1] == {"name": "HOME", "value": "/root"}
    assert out["args"] == ["--password", REDACTED, "--host", "db"]
    assert out["sshpass"][:2] == ["/usr/bin/sshpass", "-p"]


@pytest.mark.parametrize(
    "harmless",
    [
        "docker run -p8080:80 nginx",
        "ssh -p 22 host",
        "find . -print",
        "gcc -pthread x.c",
        "password reset requested by alice",
        "the token expired",
        "user=alice logged in",
        "bypass=false",
        "max_tokens=1000",
        "docker login --password-stdin registry.example",
        "password_changed for alice",
    ],
)
def test_lookalikes_survive(harmless):
    assert redact_text(harmless) == harmless


def test_yaml_block_scalar_keeps_the_rest_of_the_document():
    doc = "db:\n  password: |\n    line1Secret9\n    line2Secret9\n  host: db\n"
    out = redact_text(doc)
    assert "Secret9" not in out
    assert "host: db" in out
