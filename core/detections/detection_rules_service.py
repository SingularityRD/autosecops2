"""
Detection Rules Service - Manages detection rule sources (git repos, local directories).

Persists source metadata to ~/.vigil/detection_sources.json.
Provides CRUD operations, git pull updates, and builds env vars for Security-Detections-MCP.
"""

import json
import logging
import os
import re
import subprocess
import uuid
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from core.config import _safe_home, get_settings, vigil_path
from core.platform.url_safety import (
    parse_networks,
    resolve_allowed_addresses,
)

logger = logging.getLogger(__name__)

# Default detection repos that match the existing setup
DEFAULT_SOURCES = [
    {
        "name": "Sigma Rules",
        "type": "git",
        "git_url": "https://github.com/SigmaHQ/sigma.git",
        "format": "sigma",
        "subdirectory": "rules",
        "clone_name": "sigma",
    },
    {
        "name": "Splunk ESCU",
        "type": "git",
        "git_url": "https://github.com/splunk/security_content.git",
        "format": "splunk",
        "subdirectory": "detections",
        "clone_name": "security_content",
        "story_subdirectory": "stories",
    },
    {
        "name": "Elastic Rules",
        "type": "git",
        "git_url": "https://github.com/elastic/detection-rules.git",
        "format": "elastic",
        "subdirectory": "rules",
        "clone_name": "detection-rules",
    },
    {
        "name": "KQL Queries",
        "type": "git",
        "git_url": "https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules.git",
        "format": "kql",
        "subdirectory": "",
        "clone_name": "Hunting-Queries-Detection-Rules",
    },
]

# Names a git clone may take under base_dir (derived from the repo URL).
_CLONE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

LOCAL_ROOTS_ENV = "VIGIL_DETECTION_LOCAL_ROOTS"
GIT_ALLOWED_CIDRS_ENV = "VIGIL_DETECTION_GIT_ALLOWED_CIDRS"

# --- Git source safety (W0.11) ---------------------------------------------
# The URL of a git source reaches ``git clone`` on the API host. git treats a
# value such as ``ext::sh -c ...`` as a transport that runs a command, and one
# starting with ``-`` as an option (``--upload-pack=...``). So a git source is
# an ``https://`` URL and nothing else; local rule directories are added as
# ``type='local'`` sources, which never run git. Every git invocation also
# carries the restrictions below, so a URL that predates this check (stored in
# detection_sources.json, or the origin of an existing clone) cannot slip past.
_GIT_URL_MAX = 2048
_GIT_CLONE_TIMEOUT = 300
_GIT_PULL_TIMEOUT = 120
# fmt: off
_GIT_SAFE_CONFIG = (
    "-c", "protocol.allow=never",
    "-c", "protocol.https.allow=always",
    "-c", "protocol.ext.allow=never",
    "-c", "protocol.file.allow=never",
    "-c", "http.followRedirects=false",
    "-c", "submodule.recurse=false",
    "-c", "core.hooksPath=/dev/null",
)
# fmt: on


def validate_git_url(url: Optional[str]) -> str:
    """Syntax check for a git source URL. Returns it; raises ValueError.

    Only ``https://host/path``: no other scheme or transport, no credentials,
    query or fragment, no whitespace or control characters, no leading ``-``.
    """
    if not url or not isinstance(url, str):
        raise ValueError("Git URL is required for type 'git'")
    if len(url) > _GIT_URL_MAX:
        raise ValueError("Git URL is too long")
    if url.startswith("-") or any(c.isspace() or ord(c) < 0x20 for c in url):
        raise ValueError("Git URL must be a plain https:// URL")
    try:
        parts = urlsplit(url)
        parts.port  # noqa: B018 - raises ValueError on a bad port
    except ValueError as exc:
        raise ValueError("Git URL is not a valid URL") from exc
    if parts.scheme != "https":
        raise ValueError(
            "Git URL must start with https:// (add a local directory as a "
            "'local' source instead)"
        )
    if not parts.hostname or parts.hostname.startswith("-"):
        raise ValueError("Git URL is missing a host")
    if parts.username is not None or parts.password is not None:
        raise ValueError("Git URL must not include credentials")
    if parts.query or parts.fragment:
        raise ValueError("Git URL must not include a query or fragment")
    return url


def _git_allowed_networks() -> tuple:
    raw = get_settings().vigil_detection_git_allowed_cidrs
    try:
        return parse_networks(raw)
    except ValueError:
        logger.error(
            f"{GIT_ALLOWED_CIDRS_ENV} is not a list of CIDRs; no private git hosts allowed"
        )
        return ()


def check_git_url(url: Optional[str]) -> List[str]:
    """``validate_git_url`` plus the SSRF check: the addresses git may connect to.

    The host must resolve, and only to public addresses (or ones inside
    ``VIGIL_DETECTION_GIT_ALLOWED_CIDRS``; never the cloud-metadata address).
    Raises ValueError (``UrlSafetyError`` is one).
    """
    parts = urlsplit(validate_git_url(url))
    return resolve_allowed_addresses(
        parts.hostname, parts.port or 443, allowed_networks=_git_allowed_networks()
    )


def _git_env() -> Dict[str, str]:
    """Environment for every git subprocess: https only, never prompt."""
    env = dict(os.environ)
    env.update(
        {
            "GIT_ALLOW_PROTOCOL": "https",
            "GIT_PROTOCOL_FROM_USER": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "",
            "SSH_ASKPASS": "",
        }
    )
    return env


def _pin_resolve(url: str, addresses: List[str]) -> List[str]:
    """``-c http.curloptResolve=host:port:addr``: git connects to what was checked."""
    if not addresses:
        return []
    parts = urlsplit(url)
    addr = addresses[0]
    if ":" in addr:
        addr = f"[{addr}]"
    return ["-c", f"http.curloptResolve={parts.hostname}:{parts.port or 443}:{addr}"]


# File extensions per format
FORMAT_EXTENSIONS = {
    "sigma": [".yml"],
    "splunk": [".yml"],
    "elastic": [".toml"],
    "kql": [".yaml", ".kql", ".md"],
    "auto": [".yml", ".yaml", ".toml", ".kql", ".md"],
}

# MCP env var name per format
FORMAT_ENV_VARS = {
    "sigma": "SIGMA_PATHS",
    "splunk": "SPLUNK_PATHS",
    "elastic": "ELASTIC_PATHS",
    "kql": "KQL_PATHS",
}


_CONFIG_FILENAME = "detection_sources.json"


class DetectionRulesService:
    """Service for managing detection rule sources."""

    def __init__(self):
        self.config_path = vigil_path(_CONFIG_FILENAME)
        self.base_dir = _safe_home() / "security-detections"
        self.sources: List[Dict[str, Any]] = []
        self._load_config()

    def _load_config(self):
        """Load sources from config, rescanning them against disk; seed on first run."""
        if self.config_path.exists():
            try:
                with open(self.config_path, "r") as f:
                    data = json.load(f)
                self.sources = data.get("sources", [])
                logger.info(
                    f"Loaded {len(self.sources)} detection rule sources from config"
                )
            except Exception as e:
                logger.error(f"Error loading detection sources config: {e}")
            else:
                # Outside the try: a rescan failure must not fall through to
                # _seed_defaults, which would overwrite the user's sources.
                # The saved status is a snapshot from whenever the file was last
                # written; repos cloned since then (#968) only show up if we look.
                self.rescan_sources()
                return

        # First run or corrupt config -- seed defaults
        logger.info("No detection sources config found, seeding defaults")
        self._seed_defaults()

    def reload(self):
        """Re-read the config file and rescan every source against disk."""
        self._load_config()

    def rescan_sources(self):
        """Re-derive status and rule_count for every source from what is on disk."""
        changed = False
        for source in self.sources:
            local_path = source.get("local_path")
            if not local_path:
                continue
            local_dir = Path(local_path)
            if local_dir.exists():
                try:
                    count = self._count_rules(
                        local_dir,
                        source.get("format", "auto"),
                        source.get("subdirectory", ""),
                    )
                    status = "ready"
                except ValueError:
                    # A stored subdirectory that leaves the source is not scanned.
                    status, count = "error", 0
            else:
                # A git source can still be cloned; a local path that vanished cannot.
                status = "not_cloned" if source.get("type") == "git" else "error"
                count = 0
            if status == source.get("status") and count == source.get("rule_count"):
                continue
            logger.info(
                f"Rescanned {source.get('name')}: {source.get('status')} -> {status}"
                f" ({count} rules)"
            )
            if status == "ready" and source.get("status") != "ready":
                source["last_updated"] = datetime.now().isoformat()
            source["status"], source["rule_count"] = status, count
            changed = True
        # Only write when something moved: this runs on every construction, and
        # the service is built in more than one process.
        if changed:
            self._save_config()

    def _seed_defaults(self):
        """Seed default sources based on existing repos on disk."""
        self.sources = []
        for default in DEFAULT_SOURCES:
            clone_dir = self.base_dir / default["clone_name"]
            source = {
                "id": str(uuid.uuid4())[:8],
                "name": default["name"],
                "type": default["type"],
                "git_url": default["git_url"],
                "format": default["format"],
                "subdirectory": default.get("subdirectory", ""),
                "story_subdirectory": default.get("story_subdirectory", ""),
                "clone_name": default["clone_name"],
                "local_path": str(clone_dir),
                "rule_count": 0,
                "last_updated": None,
                "status": "unknown",
            }

            # Check if repo already exists on disk
            if clone_dir.exists():
                source["status"] = "ready"
                source["rule_count"] = self._count_rules(
                    clone_dir, default["format"], default.get("subdirectory", "")
                )
                source["last_updated"] = datetime.now().isoformat()
                logger.info(
                    f"Found existing repo: {default['name']} ({source['rule_count']} rules)"
                )
            else:
                source["status"] = "not_cloned"
                logger.info(f"Default source not yet cloned: {default['name']}")

            self.sources.append(source)

        self._save_config()

    def _save_config(self):
        # Resolved here, not in __init__: write=True creates the directory, and
        # this service is constructed on the API startup path (#695).
        try:
            with open(vigil_path(_CONFIG_FILENAME, write=True), "w") as f:
                json.dump({"sources": self.sources, "version": 1}, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving detection sources config: {e}")

    @staticmethod
    def _under(base: str, rel: str = "") -> str:
        """Real path of ``rel`` under ``base``; ValueError if it leaves ``base``.

        The check stays inline so every caller gets a path that is known to
        be contained, whatever the source of ``rel``.
        """
        root = os.path.realpath(base)
        full = os.path.realpath(os.path.join(root, rel))
        if full == root:
            return root
        if not full.startswith(root + os.sep):
            raise ValueError(f"Path must stay inside {base}: {rel}")
        return full

    def _local_roots(self) -> List[str]:
        extra = get_settings().vigil_detection_local_roots
        return [str(_safe_home())] + [r for r in extra.split(os.pathsep) if r]

    def _local_root(self, path: str) -> str:
        """Real path of a local source directory, which must sit under an allowed root."""
        for root in self._local_roots():
            try:
                return self._under(root, os.path.expanduser(path))
            except ValueError:
                continue
        raise ValueError(
            f"Local path must be under your home directory or a root listed in "
            f"{LOCAL_ROOTS_ENV}: {path}"
        )

    def _count_rules(self, base_path: Path, fmt: str, subdirectory: str = "") -> int:
        """Count rule files in a directory by format."""
        target = Path(self._under(str(base_path), subdirectory))
        if not target.exists():
            return 0

        extensions = FORMAT_EXTENSIONS.get(fmt, FORMAT_EXTENSIONS["auto"])
        count = 0
        for ext in extensions:
            count += len(list(target.rglob(f"*{ext}")))
        return count

    def _get_rules_path(self, source: Dict) -> str:
        """Get the actual rules path for a source (base + subdirectory)."""
        base = Path(source["local_path"])
        subdir = source.get("subdirectory", "")
        if subdir:
            return str(base / subdir)
        return str(base)

    def _get_story_path(self, source: Dict) -> Optional[str]:
        """Get the story path for a source (Splunk only)."""
        story_sub = source.get("story_subdirectory", "")
        if story_sub:
            return str(Path(source["local_path"]) / story_sub)
        return None

    # --- Public API ---

    def list_sources(self) -> List[Dict[str, Any]]:
        """Return all registered rule sources with metadata."""
        return self.sources

    def get_source(self, source_id: str) -> Optional[Dict[str, Any]]:
        """Get a single source by ID."""
        for source in self.sources:
            if source["id"] == source_id:
                return source
        return None

    def _rules_dir_key(self, local_path: str, subdirectory: str) -> str:
        """Resolved rules directory: a source's identity together with its format."""
        return self._under(local_path, subdirectory)

    def _find_existing(
        self, local_path: str, subdirectory: str, format: str
    ) -> Optional[Dict[str, Any]]:
        key = self._rules_dir_key(local_path, subdirectory)
        for source in self.sources:
            if source["format"] != format:
                continue
            if (
                self._rules_dir_key(
                    source["local_path"], source.get("subdirectory", "")
                )
                == key
            ):
                return source
        return None

    def add_source(
        self,
        name: str,
        source_type: str,
        format: str,
        url: Optional[str] = None,
        path: Optional[str] = None,
        subdirectory: str = "",
        story_subdirectory: str = "",
    ) -> Dict[str, Any]:
        """
        Add a new detection rule source.

        Args:
            name: Display name for the source
            source_type: 'git' or 'local'
            format: 'sigma', 'splunk', 'elastic', 'kql', or 'auto'
            url: Git repository URL (required for type='git')
            path: Local directory path (required for type='local')
            subdirectory: Subdirectory within the repo/path containing rules
            story_subdirectory: Subdirectory for Splunk stories (optional)
        """
        source_id = str(uuid.uuid4())[:8]

        if source_type == "git":
            # Refuse anything but a plain https:// URL before it is stored or
            # reaches git (W0.11); _git_clone repeats this with the SSRF check.
            url = validate_git_url(url)
            # Derive clone name from URL
            clone_name = url.rstrip("/").split("/")[-1].replace(".git", "")
            if not _CLONE_NAME_RE.match(clone_name):
                raise ValueError(f"Cannot derive a clone directory from URL: {url}")
            local_path = self._under(str(self.base_dir), clone_name)
        elif source_type == "local":
            if not path:
                raise ValueError("Path is required for type 'local'")
            local_path = self._local_root(path)
            clone_name = Path(local_path).name
        else:
            raise ValueError(f"Invalid source type: {source_type}")

        # Reject subdirectories that climb out of the source before they are stored.
        self._under(local_path, subdirectory)
        self._under(local_path, story_subdirectory)

        # Idempotent on (resolved rules directory, format): re-registering the same
        # directory refreshes the existing entry instead of appending a duplicate.
        existing = self._find_existing(local_path, subdirectory, format)
        if existing is not None:
            if not Path(local_path).exists():
                if source_type != "git":
                    raise ValueError(f"Local path does not exist: {local_path}")
                self._git_clone(url, local_path)
            existing["rule_count"] = self._count_rules(
                Path(local_path), format, subdirectory
            )
            existing["last_updated"] = datetime.now().isoformat()
            existing["status"] = "ready"
            self._save_config()
            logger.info(
                f"Source already registered as {existing['name']!r} "
                f"({existing['id']}); not adding {name!r} again"
            )
            return existing

        source = {
            "id": source_id,
            "name": name,
            "type": source_type,
            "git_url": url or "",
            "format": format,
            "subdirectory": subdirectory,
            "story_subdirectory": story_subdirectory,
            "clone_name": clone_name,
            "local_path": local_path,
            "rule_count": 0,
            "last_updated": None,
            "status": "not_cloned" if source_type == "git" else "unknown",
        }

        # If git, clone the repo
        if source_type == "git":
            clone_dir = Path(local_path)
            if clone_dir.exists():
                # Already cloned, just scan
                source["status"] = "ready"
                source["rule_count"] = self._count_rules(
                    clone_dir, format, subdirectory
                )
                source["last_updated"] = datetime.now().isoformat()
            else:
                try:
                    self._git_clone(url, local_path)
                    source["status"] = "ready"
                    source["rule_count"] = self._count_rules(
                        clone_dir, format, subdirectory
                    )
                    source["last_updated"] = datetime.now().isoformat()
                except Exception as e:
                    source["status"] = "error"
                    logger.error(f"Failed to clone {url}: {e}")
                    raise
        elif source_type == "local":
            local_dir = Path(local_path)
            if local_dir.exists():
                source["status"] = "ready"
                source["rule_count"] = self._count_rules(
                    local_dir, format, subdirectory
                )
                source["last_updated"] = datetime.now().isoformat()
            else:
                source["status"] = "error"
                raise ValueError(f"Local path does not exist: {local_path}")

        self.sources.append(source)
        self._save_config()
        logger.info(f"Added source: {name} ({source['rule_count']} rules)")
        return source

    def remove_source(self, source_id: str, delete_files: bool = False) -> bool:
        """Remove a rule source by ID."""
        source = self.get_source(source_id)
        if not source:
            return False

        if delete_files and source["type"] == "git":
            import shutil

            try:
                clone_dir = Path(self._under(str(self.base_dir), source["local_path"]))
            except ValueError:
                logger.error(
                    f"Refusing to delete {source['local_path']}: outside {self.base_dir}"
                )
                clone_dir = None
            if clone_dir and clone_dir.exists():
                try:
                    shutil.rmtree(clone_dir)
                    logger.info(f"Deleted cloned directory: {clone_dir}")
                except Exception as e:
                    logger.error(f"Failed to delete {clone_dir}: {e}")

        self.sources = [s for s in self.sources if s["id"] != source_id]
        self._save_config()
        logger.info(f"Removed source: {source['name']}")
        return True

    def update_source(self, source_id: str) -> Dict[str, Any]:
        """Update a single source (git pull or rescan)."""
        source = self.get_source(source_id)
        if not source:
            raise ValueError(f"Source not found: {source_id}")

        if source["type"] == "git":
            clone_dir = Path(source["local_path"])
            if not clone_dir.exists():
                # Not cloned yet, clone it
                self._git_clone(source["git_url"], source["local_path"])
            else:
                # Git pull
                self._git_pull(source["local_path"])

        # Rescan rule count
        source["rule_count"] = self._count_rules(
            Path(source["local_path"]), source["format"], source.get("subdirectory", "")
        )
        source["last_updated"] = datetime.now().isoformat()
        source["status"] = "ready"
        self._save_config()
        logger.info(f"Updated source: {source['name']} ({source['rule_count']} rules)")
        return source

    def update_all(self) -> List[Dict[str, Any]]:
        """Update all sources."""
        results = []
        for source in self.sources:
            try:
                updated = self.update_source(source["id"])
                results.append(
                    {
                        "id": source["id"],
                        "name": source["name"],
                        "success": True,
                        "rule_count": updated["rule_count"],
                    }
                )
            except Exception as e:
                results.append(
                    {
                        "id": source["id"],
                        "name": source["name"],
                        "success": False,
                        "error": str(e),
                    }
                )
                logger.error(f"Failed to update {source['name']}: {e}")
        return results

    def get_stats(self) -> Dict[str, Any]:
        """Get aggregate detection rule statistics."""
        total = 0
        by_format = defaultdict(int)
        by_source = []

        for source in self.sources:
            count = source.get("rule_count", 0)
            total += count
            by_format[source["format"]] += count
            by_source.append(
                {
                    "name": source["name"],
                    "format": source["format"],
                    "count": count,
                    "status": source.get("status", "unknown"),
                }
            )

        return {
            "total_rules": total,
            "sources_count": len(self.sources),
            "by_format": dict(by_format),
            "sources": by_source,
        }

    def get_mcp_env_vars(self) -> Dict[str, str]:
        """
        Build environment variable dict for Security-Detections-MCP.

        Combines multiple paths per format with commas, matching the MCP server's
        expected SIGMA_PATHS, SPLUNK_PATHS, ELASTIC_PATHS, KQL_PATHS, STORY_PATHS format.
        """
        paths_by_format: Dict[str, List[str]] = defaultdict(list)
        story_paths: List[str] = []

        for source in self.sources:
            if source.get("status") != "ready":
                continue

            rules_path = self._get_rules_path(source)
            if Path(rules_path).exists():
                fmt = source["format"]
                if fmt in FORMAT_ENV_VARS:
                    paths_by_format[fmt].append(rules_path)

            # Collect story paths (Splunk)
            story_path = self._get_story_path(source)
            if story_path and Path(story_path).exists():
                story_paths.append(story_path)

        env_vars = {}
        for fmt, env_var in FORMAT_ENV_VARS.items():
            if paths_by_format[fmt]:
                env_vars[env_var] = ",".join(paths_by_format[fmt])

        if story_paths:
            env_vars["STORY_PATHS"] = ",".join(story_paths)

        return env_vars

    # --- Git operations ---

    def _git_clone(self, url: str, target_path: str):
        """Shallow-clone an https git repository, refusing any other URL."""
        addresses = check_git_url(url)
        target_path = self._under(str(self.base_dir), target_path)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Cloning {url} to {target_path}...")
        result = subprocess.run(
            [
                "git",
                *_GIT_SAFE_CONFIG,
                *_pin_resolve(url, addresses),
                "clone",
                "--quiet",
                "--depth",
                "1",
                "--single-branch",
                "--no-recurse-submodules",
                "--",
                url,
                target_path,
            ],
            capture_output=True,
            text=True,
            timeout=_GIT_CLONE_TIMEOUT,
            env=_git_env(),
            stdin=subprocess.DEVNULL,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Git clone failed: {result.stderr.strip()}")
        logger.info(f"Successfully cloned {url}")

    def _git_remote_url(self, repo_path: str) -> str:
        """The ``origin`` URL a pull in ``repo_path`` would fetch from."""
        result = subprocess.run(
            ["git", "config", "--get", "remote.origin.url"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=30,
            env=_git_env(),
            stdin=subprocess.DEVNULL,
        )
        return result.stdout.strip() if result.returncode == 0 else ""

    def _git_pull(self, repo_path: str):
        """Pull latest changes, only from an https origin that passes the URL checks."""
        origin = self._git_remote_url(repo_path)
        try:
            addresses = check_git_url(origin)
        except ValueError as exc:
            raise ValueError(
                f"Refusing to pull {repo_path}: its origin is not an allowed "
                f"https URL ({exc})"
            ) from exc
        logger.info(f"Pulling updates in {repo_path}...")
        result = subprocess.run(
            [
                "git",
                *_GIT_SAFE_CONFIG,
                *_pin_resolve(origin, addresses),
                "pull",
                "--quiet",
                "--ff-only",
                "--no-recurse-submodules",
            ],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=_GIT_PULL_TIMEOUT,
            env=_git_env(),
            stdin=subprocess.DEVNULL,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Git pull failed: {result.stderr.strip()}")
        logger.info(f"Successfully pulled updates in {repo_path}")


# Global singleton
