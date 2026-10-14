"""Round-5 regression corpora for audit-export redaction (WP w3.6).

Two corpora from the round-5 verifier, kept here verbatim so they cannot
regress:

* LEAKS: 152 carrier strings (CLI argv, config formats, encodings, nesting,
  token shapes). The secret must be gone from free text (``redact_text``)
  and from ``details`` (``Redactor.value``).
* FALSE POSITIVES: realistic SOC audit text and detail dicts (hash IOCs,
  registry keys, Suricata signatures, status words, counts, prose names)
  that must come out unchanged.

Token-shaped literals are split (``"gh" "s_..."``) so that repository push
protection does not flag this file.
"""

from __future__ import annotations

import base64
import json
from dataclasses import replace

import pytest

from core.compliance.audit_export import (
    REDACTED,
    AuditEvent,
    Redactor,
    identifier_strength,
    redact_text,
)

pytestmark = pytest.mark.unit

S = "Zq7Vx2Lm9Rt4"  # the fixed secret most carriers hide
C: list[tuple[str, str, str]] = []


def add(label, text, secret=S):
    C.append((label, text, secret))


def b64(s):
    return base64.b64encode(s.encode()).decode()


pem = (
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7bq"
    + "x" * 40
    + "\n-----END RSA PRIVATE KEY-----\n"
)

# CLI forms
add("curl -u", f"curl -u admin:{S} https://x/api")
add("curl --user", f"curl --user admin:{S} https://x")
add("redis-cli -a", f"redis-cli -h r -a {S} ping")
add("sqlcmd -P", f"sqlcmd -S db -U sa -P {S} -Q 'select 1'")
add("ldapsearch -w", f"ldapsearch -x -D cn=admin,dc=x -w {S} -b dc=x")
add("docker login -p", f"docker login -u bob -p {S} registry.example.com")
add("mongo -p space", f"mongo -u admin -p {S} --authenticationDatabase admin")
add("psexec -p", f"psexec \\\\host -u admin -p {S} cmd")
add("smbclient U%", f"smbclient //srv/share -U alice%{S}")
add("rabbitmqctl add_user", f"rabbitmqctl add_user svc {S}")
add("rabbitmqctl change_password", f"rabbitmqctl change_password svc {S}")
add("net user /add", f"net user backdoor {S} /add")
add("chpasswd", f"echo 'root:{S}' | chpasswd")
add("ssh-keygen -N", f"ssh-keygen -t ed25519 -N '{S}' -f k")
add("zip -P", f"zip -P {S} out.zip f")
add("7z -p", f"7z a -p{S} out.7z f")
add("openssl passin", f"openssl rsa -in k.pem -passin pass:{S}")
add("openssl -k", f"openssl enc -aes-256-cbc -k {S} -in f")
add("keytool storepass", f"keytool -list -keystore k.jks -storepass {S}")
add("az login -p", f"az login --service-principal -u appid -p {S} --tenant t")
add("az login password=", f"az login -u u@x.com --password {S}")
add("aws configure set", f"aws configure set aws_secret_access_key {S}")
add("kubectl --token=", f"kubectl --token={S} get pods")
add(
    "kubectl from-literal",
    f"kubectl create secret generic db --from-literal=password={S}",
)
add(
    "kubectl from-literal key",
    f"kubectl create secret generic db --from-literal=DB_PASS={S}",
)
add("helm --set", f"helm upgrade x --set auth.rootPassword={S}")
add(
    "helm --set-string",
    f"helm upgrade x --set-string postgresql.auth.postgresPassword={S}",
)
add(
    "ansible extra vars",
    f'ansible-playbook p.yml --extra-vars "ansible_become_pass={S}"',
)
add("ansible inventory", f"web1 ansible_host=10.0.0.1 ansible_password={S}")
add("vault login", f"vault login {S}")
add("vault kv put", f"vault kv put secret/db password={S}")
add("gh auth --with-token", f"echo {S} | gh auth login --with-token")
add("wget http-password", f"wget --http-user=u --http-password={S} https://x")
add("wget --password space", f"wget --user=u --password {S} https://x")
add(
    "git -c http.extraheader",
    f"git -c http.extraheader='AUTHORIZATION: bearer {S}' clone x",
)
add("mysqladmin password", f"mysqladmin -u root password {S}")
add("pg createuser sql", f"psql -c \"CREATE USER bob WITH PASSWORD '{S}'\"")
add("oracle identified by", f"ALTER USER scott IDENTIFIED BY {S};")
add("mysql set password", f"SET PASSWORD FOR 'bob'@'%' = PASSWORD('{S}');")
add("mssql create login", f"CREATE LOGIN bob WITH PASSWORD = '{S}';")
add("powershell securestring", f"$p = ConvertTo-SecureString '{S}' -AsPlainText -Force")
add(
    "powershell PSCredential",
    f"New-Object System.Management.Automation.PSCredential('bob', (ConvertTo-SecureString '{S}' -AsPlainText -Force))",
)
add("schtasks /RP", f"schtasks /create /tn t /tr x /ru admin /rp {S}")
add("wmic /password:", f"wmic /node:h /user:admin /password:{S} process list")
add("runas savecred n/a; cmdkey", f"cmdkey /add:srv /user:admin /pass:{S}")
add("sshpass -e env", f"SSHPASS={S} sshpass -e ssh host")
add("htpasswd -bc", f"htpasswd -bc /etc/nginx/.htpasswd admin {S}")
add("ftp url", f"ftp://anonymous:{S}@ftp.example.com/pub")
add("smb url", f"smb://DOMAIN;alice:{S}@fileserver/share")
add("sentry dsn", f"SENTRY_DSN=https://{S}@o1.ingest.sentry.io/1")
# config file formats
add("netrc", f"machine api.github.com login bob password {S}")
add("pgpass", f"db.internal:5432:*:postgres:{S}")
add("npmrc authToken", f"//registry.npmjs.org/:_authToken={S}")
add("pypirc", f"[pypi]\nusername = __token__\npassword = {S}")
add(
    "docker config auth",
    json.dumps({"auths": {"r.io": {"auth": b64("bob:" + S)}}}),
    b64("bob:" + S),
)
add(
    "dockerconfigjson b64",
    ".dockerconfigjson: " + b64(json.dumps({"auths": {"r.io": {"password": S}}})),
    b64(json.dumps({"auths": {"r.io": {"password": S}}}))[:30],
)
add(
    "k8s secret data b64",
    f"apiVersion: v1\nkind: Secret\ndata:\n  password: {b64(S)}\n",
    b64(S),
)
add("k8s stringData", f"stringData:\n  DB_PASSWORD: {S}\n")
add("kubeconfig token", f"users:\n- name: u\n  user:\n    token: {S}\n")
add("kubeconfig client-key-data", f"    client-key-data: {b64(pem)}\n", b64(pem)[:40])
add("tfvars", f'db_password = "{S}"')
add("HCL heredoc", f"password = <<EOF\n{S}\nEOF")
add("spring properties", f"spring.datasource.password={S}")
add("java -D truststore", f"java -Djavax.net.ssl.trustStorePassword={S} -jar app.jar")
add("django settings", f"SECRET_KEY = '{S}'")
add("rails secret_key_base", f"secret_key_base: {S}")
add("ini section", f"[database]\nhost=db\npassword={S}\n")
add("toml", f'[db]\npassword = "{S}"')
add("yaml next-line quoted", f'password:\n  "{S}"\n')
add("yaml list env", f"env:\n  - name: API_TOKEN\n    value: {S}\n")
add(
    "tomcat-users xml attr",
    f'<user username="admin" password="{S}" roles="manager-gui"/>',
)
add(
    "maven settings",
    f"<server><id>x</id><username>u</username><password>{S}</password></server>",
)
add(
    "web.config connstr",
    f'<add name="Db" connectionString="Server=x;User Id=sa;Password={S};"/>',
)
add("php array", f"'password' => '{S}',")
add("ruby hash rocket", f':password => "{S}"')
add("perl hash", f"password => '{S}'")
add("go struct dump", f"&{{User:bob Password:{S} Host:db}}")
add("python repr kwargs", f"connect(host='db', user='bob', passwd='{S}')")
add("python dict repr", f"{{'secret_key': '{S}'}}")
add("env NODE", f"export NPM_TOKEN={S}")
add("DD_API_KEY", f"DD_API_KEY={S}")
add("DD_APP_KEY", f"DD_APP_KEY={S}")
add("NEW_RELIC_LICENSE_KEY", f"NEW_RELIC_LICENSE_KEY={S}")
add("Ocp-Apim-Subscription-Key", f"Ocp-Apim-Subscription-Key: {S}")
add("x-functions-key", f"x-functions-key: {S}")
add("azure functions ?code=", f"https://fn.azurewebsites.net/api/h?code={S}")
add("X-Auth-Key cloudflare", f"X-Auth-Key: {S}")
add("PRIVATE-TOKEN gitlab", f"PRIVATE-TOKEN: {S}")
add("X-Vault-Token", f"X-Vault-Token: {S}")
add("X-Shopify-Access-Token", f"X-Shopify-Access-Token: {S}")
add("JSESSIONID cookie", f"Cookie: JSESSIONID={S}")
add("PHPSESSID", f"PHPSESSID={S}")
add("connect.sid", f"connect.sid={S}")
add(
    "telegram bot url",
    f"https://api.telegram.org/bot123456789:AAH{S}abcdefghijklmnopqr/sendMessage",
    f"AAH{S}abcdefghijklmnopqr",
)
add(
    "mailgun key-",
    "key" "-3ax6xnjp29jd6fds4gc373sgvjxteol0",
    "key" "-3ax6xnjp29jd6fds4gc373sgvjxteol0",
)
add("twilio auth token sid", "twilio -a AC" + "abcdef0123456789abcdef0123456789" + f" -t {S}")
add(
    "atlassian token",
    "ATA" "TT3xFfGF0aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
    "ATA" "TT3xFfGF0aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
)
add(
    "tailscale authkey",
    "tskey" "-auth-kAbCdEf1CNTRL-AbCdEfGhIjKlMnOpQrStUvWxYz012345",
    "tskey" "-auth-kAbCdEf1CNTRL-AbCdEfGhIjKlMnOpQrStUvWxYz012345",
)
add(
    "age secret key",
    "AGE-SECRET" "-KEY-1QQPQZ8Y4T0XJ4L3E2NFP3XJ8Z4Q5W6E7R8T9Y0U1I2O3P4A5S6D7F8GH",
    "AGE-SECRET" "-KEY-1QQPQZ8Y4T0XJ4L3E2NFP3XJ8Z4Q5W6E7R8T9Y0U1I2O3P4A5S6D7F8GH",
)
add("square token", "sq0" "atp-AbCdEfGhIjKlMnOpQrStUv", "sq0" "atp-AbCdEfGhIjKlMnOpQrStUv")
add(
    "facebook token",
    "EAACEd" "Eose0cBAAbCdEfGhIjKlMnOpQrStUvWxYz0123",
    "EAACEd" "Eose0cBAAbCdEfGhIjKlMnOpQrStUvWxYz0123",
)
add(
    "azure ad client secret shape",
    "secret was abc8Q~AbCdEfGhIjKlMnOpQrStUvWxYz0123_45",
    "abc8Q~AbCdEfGhIjKlMnOpQrStUvWxYz0123_45",
)
add(
    "openai sess",
    "sess" "-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd",
    "sess" "-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd",
)
add(
    "anthropic admin",
    "sk-" "ant-admin01-AbCdEfGhIjKlMnOpQrStUvWxYz0123",
    "AbCdEfGhIjKlMnOpQrStUvWxYz0123",
)
add("gitlab runner token", "gl" "rt-AbCdEfGhIjKlMnOpQrSt", "gl" "rt-AbCdEfGhIjKlMnOpQrSt")
add(
    "github fine app token",
    "gh" "s_AbCdEfGhIjKlMnOpQrStUvWxYz012345",
    "gh" "s_AbCdEfGhIjKlMnOpQrStUvWxYz012345",
)
add(
    "JWK private d",
    json.dumps(
        {
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "d": "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
        }
    ),
    "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
)
add(
    "putty ppk",
    "PuTTY-User-Key-File-3: ssh-rsa\nEncryption: none\nPrivate-Lines: 1\nAAAAgQCZzq7Vx2Lm9Rt4abcdefghijkl\nPrivate-MAC: ab",
    "AAAAgQCZzq7Vx2Lm9Rt4abcdefghijkl",
)
add(
    "pem in json escaped twice",
    json.dumps(json.dumps({"k": pem})),
    "MIIEowIBAAKCAQEA7bq",
)
# encodings / nesting
add("json in string", json.dumps({"payload": json.dumps({"password": S})}))
add(
    "json in json in string",
    json.dumps({"p": json.dumps({"q": json.dumps({"password": S})})}),
)
add("unicode escaped sep", f"password\\u003d{S}")
add("unicode escaped key json", '{"pass\\u0077ord": "%s"}' % S)
add("html entity sep", f"password&#61;{S}")
add("hex escaped", f"password\\x3d{S}")
add("b64 of password=", f"payload={b64('password=' + S)}", b64("password=" + S))
add("b64 basic in url", f"https://x/?auth={b64('u:' + S)}", b64("u:" + S))
add("triple percent", "password%25253D" + S)
add("form body", f"username=bob&password={S}&remember=1")
add(
    "graphql vars",
    json.dumps({"query": "mutation{login}", "variables": {"input": {"password": S}}}),
)
add("header list", json.dumps([["Authorization", f"Bearer {S}"]]))
add("header list kv dict", json.dumps({"headers": [{"name": "X-Api-Key", "value": S}]}))
add("args list -P", json.dumps(["sqlcmd", "-U", "sa", "-P", S]))
add("args list redis -a", json.dumps(["redis-cli", "-a", S]))
add("args --password=", json.dumps(["app", f"--password={S}"]))
add("windows cmdline quoted", f'"C:\\tools\\app.exe" /p:"{S}"')
add("msbuild /p:Password", f"msbuild /p:DeployPassword={S}")
add("password is prose", f"the new password is {S}")
add("pw colon prose", f"pw: {S}")
add("passcode", f"passcode={S}")
add("passkey", f"passkey={S}")
add("apiSecret camel", f"apiSecret={S}")
add("clientKey", f"clientKey={S}")
add("privKey", f"privKey={S}")
add("encKey", f"encryption-key: {S}")
add("hmacKey", f"hmac_key={S}")
add("bot_token", f"bot_token={S}")
add("authKey", f"authKey={S}")
add("ssh_pass", f"ssh_pass={S}")
add("Pwd uppercase odbc var", f"PWD={S}")
add("tab separated", f"password\t\t{S}")
add("password with spaces in quotes", f"password='{S} more words'")
add("password unquoted spaces after colon", f"Password: {S} (temporary)")
add("secret with semicolon", f"password=ab;{S}", S)
add("value starting with dash", f"--password -{S}")
add("value with quote inside", f"password=it's{S}")
add("long ident >96", "x" * 100 + f"_password={S}")
add("xml cdata", f"<password><![CDATA[{S}]]></password>")
add("xml element nested", f"<Password><Value>{S}</Value></Password>")
add("yaml anchor", f"password: &pw {S}")
add("yaml quoted key flow", f"{{password: {S}}}")
add("multiline env block", f"DB_HOST=db\nDB_PASS=\\\n{S}")


def test_leak_corpus_size():
    assert len(C) == 152


@pytest.mark.parametrize("label,text,secret", C, ids=[c[0] for c in C])
def test_leak_corpus_free_text(label, text, secret):
    assert secret not in redact_text(text)


@pytest.mark.parametrize("label,text,secret", C, ids=[c[0] for c in C])
def test_leak_corpus_details(label, text, secret):
    out = Redactor().value("", {"msg": text, "nested": [{"v": text}]})
    assert secret not in json.dumps(out)


STRUCTURED_LEAKS = [
    {"headers": [{"name": "X-Api-Key", "value": S}]},
    {"clientKey": S},
    {"hmac_key": S},
    {"privKey": S},
    {"client-key-data": S},
    {"passcode": S},
    {"license_key": S},
    {"app_key": S},
    {"subscription_key": S},
    {"auth_key": S},
    {"api_secret": S},
    {"jwk": {"kty": "RSA", "d": S}},
    {
        "env": [
            {"name": "API_TOKEN", "valueFrom": None},
            {"name": "DB_PASSWORD", "value": S},
        ]
    },
    {"argv": ["redis-cli", "-a", S]},
    {"argv": ["curl", "-u", "u:" + S]},
    {"master_password": S},
    {"keystore_pass": S},
    {"sessionToken": S},
    {"cookie_value": S},
    {"x_functions_key": S},
    {"secret_value": S},
    {"connection": "Server=x;Password=" + S},
    {"params": {"key": "password", "val": S}},
    {"k": "password", "v": S},
    {"Key": "DbPassword", "Value": S},
]


@pytest.mark.parametrize("details", STRUCTURED_LEAKS, ids=lambda d: json.dumps(d)[:40])
def test_structured_leaks(details):
    assert S not in json.dumps(Redactor().value("", details))


def test_cli_argv_keeps_the_user_and_cuts_the_password():
    out = Redactor().value("", {"argv": ["curl", "-u", "u:" + S, "https://x"]})
    assert out["argv"] == ["curl", "-u", "u:" + REDACTED, "https://x"]
    out = Redactor().value("", {"argv": ["docker", "run", "-p", "8080:80", "img"]})
    assert out["argv"] == ["docker", "run", "-p", "8080:80", "img"]


FALSE_POSITIVE_TEXT = [
    "Analyst set severity to high. Registry key: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater persists malware.",
    "Persistence via Run key=HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Suricata signature: ET MALWARE Win32/Emotet CnC Beacon matched on 10.1.2.3",
    "alert signature=ET POLICY Suspicious inbound to MSSQL port 1433",
    "auth: failed for user jdoe from 203.0.113.7 (5 attempts)",
    "auth=success method=saml",
    "Test results pass=12 fail=3 skipped=0",
    "token: expired, user prompted to re-login",
    "pin: true; host pinned to isolation VLAN",
    "Jira key: SEC-4821 linked to case",
    "sort key=created_at desc",
    "Approved isolation of host WIN-ABC123 via EDR; ticket CHG0012345",
    "User reported phishing email; password reset forced for jdoe; MFA re-enrolled",
    "Approve: block IP 198.51.100.23 on perimeter firewall port 443",
    "nmap -p443,8443 -sV 10.0.0.0/24 run by analyst",
    "ssh -p2222 admin@bastion used for triage",
    "File path /Users/JohnDoe/Library/Caches/Chrome1234 contains dropper",
    "Hash sha256=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "SHA1 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12 seen on 3 hosts",
    "Case notes: secret scanning found leaked credentials in repo acme/web; rotated secret and notified owner",
    "Session id 4f1c2a9e-1b2c-4d5e-8f90-123456789abc closed by admin",
    "Process cmdline: powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
    "Mimikatz detected: sekurlsa::logonpasswords on host DC01",
    "Token count exceeded budget for agent triage run",
    "The key finding is lateral movement from WS-17 to DC01",
    "Escalated to tier 2: key: lateral-movement, risk: high",
    "Decision: approved by bob; reason: confirmed C2 beacon to evil.example.net",
    "URL observed: /api/v2/Customers/Orders/12345/LineItemsA in proxy logs",
    "Base64 blob in email attachment name: UmVwb3J0X1EzXzIwMjZfRmluYW5jZS5wZGYuZXhl",
    "MITRE T1003.001 OS Credential Dumping: LSASS Memory",
    "User alice@example.com approved the containment action",
    "otp code 12345678 rejected (expired)",
    "kubectl logs -p deploy/api showed crash loop",
    "tar -pxvf archive.tar extracted by attacker",
    "Changed field 'auth_method' from password to sso",
    "Password policy updated: min length 14",
    "pass: 3/5 checks; fail: 2/5",
    "sig: valid",
]
# Deliberately still redacted (documented in AUDIT_EXPORT.md): an OTP code is
# a credential even when rejected, and an e-mail address in free text is PII
# while redact_pii is on (the actor field is not; see below).
INTENTIONAL = {
    "otp code 12345678 rejected (expired)",
    "User alice@example.com approved the containment action",
}


@pytest.mark.parametrize(
    "text", [t for t in FALSE_POSITIVE_TEXT if t not in INTENTIONAL]
)
def test_false_positive_text_survives(text):
    assert Redactor().text(text) == text


@pytest.mark.parametrize("text", sorted(INTENTIONAL))
def test_documented_redactions_in_text(text):
    assert Redactor().text(text) != text
    assert (
        Redactor(redact_pii=False).text("User alice@example.com approved")
        == "User alice@example.com approved"
    )


FALSE_POSITIVE_STRUCTURED = [
    {"signature": "ET MALWARE Emotet"},
    {"token_usage": 1234},
    {"tokens_used": 1234},
    {"token_count": 512},
    {"sig_id": 2024001},
    {"pin": "WIN-ABC123"},
    {"auth": "saml"},
    {"auth_method": "password"},
    {"field": "pin", "value": "WIN-1"},
    {"name": "Rotate API key", "value": "approved"},
    {"id": "pass-through", "data": {"host": "x"}},
    {"key": "credential_dumping", "value": "T1003"},
    {"mitre": {"name": "Credential Access", "id": "TA0006"}},
    {"technique": {"name": "OS Credential Dumping", "data": "lsass"}},
    {"session_id": "case-session-1"},
    {"password_changed": True},
    {"mfa_code_sent": True},
    {"cookie_consent": "accepted"},
    {"actor": "alice@example.com"},
    {"prev_hash": "ab" * 32},
]


@pytest.mark.parametrize(
    "details", FALSE_POSITIVE_STRUCTURED, ids=lambda d: json.dumps(d)[:40]
)
def test_false_positive_structured_survives(details):
    assert Redactor().value("", details) == details


@pytest.mark.parametrize(
    "ioc",
    [
        "d41d8cd98f00b204e9800998ecf8427e",  # MD5
        "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",  # SHA-1
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",  # SHA-256
        "4bf92f3577b34da6a3ce929d0e0e4736",  # W3C trace id
    ],
)
def test_hash_iocs_and_trace_ids_are_evidence_not_secrets(ioc):
    for text in (ioc, f"sha256={ioc}", f"trace_id={ioc} seen", f"IOC {ioc} on 3 hosts"):
        assert redact_text(text) == text
    assert Redactor().value("", {"sha256": ioc, "trace_id": ioc}) == {
        "sha256": ioc,
        "trace_id": ioc,
    }


def test_weak_keys_still_cut_secret_looking_values():
    assert redact_text(f"token: {S}") == f"token: {REDACTED}"
    assert redact_text("pin: 4821") == f"pin: {REDACTED}"
    assert Redactor().value("", {"signature": S, "pin": "0000"}) == {
        "signature": REDACTED,
        "pin": REDACTED,
    }


def test_identifier_strength_policy():
    for strong in (
        "password",
        "DB_PASS",
        "clientKey",
        "DD_APP_KEY",
        "bot_token",
        "PHPSESSID",
    ):
        assert identifier_strength(strong) == 2, strong
    for weak in (
        "token",
        "key",
        "auth",
        "pin",
        "signature",
        "session_id",
        "connect.sid",
    ):
        assert identifier_strength(weak) == 1, weak
    for no in (
        "token_count",
        "token_usage",
        "password_policy",
        "credential_dumping",
        "cookie_consent",
        "max_tokens",
    ):
        assert identifier_strength(no) == 0, no


def test_actor_is_never_pii_redacted_but_loses_secrets():
    from datetime import datetime, timezone

    ev = AuditEvent(
        id="config:1",
        source="config",
        category="configuration",
        action="update",
        outcome="success",
        severity=3,
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        actor="alice@example.com",
        message="changed by alice@example.com",
        details={"approved_by": "bob@example.com", "email": "carol@example.com"},
    )
    out = Redactor().event(ev)
    assert out.actor == "alice@example.com"
    assert out.details["approved_by"] == "bob@example.com"
    assert out.details["email"] == REDACTED
    assert "alice@example.com" not in out.message
    leaked = Redactor().event(replace(ev, actor="bob password=" + S))
    assert S not in leaked.actor
