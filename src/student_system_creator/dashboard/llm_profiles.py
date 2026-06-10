r"""LLM provider profiles and credential management.

Supports multiple LLM backends (AcademicCloud, TU Berlin Ollama, OpenAI, etc.)
with configurable credentials, model discovery, and health checking.

Credentials are never returned to frontend or written to tracked files.
External env folder at C:\Users\DikshyantAcharya\Personal\env can be
configured in dashboard settings.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

import requests
import yaml


@dataclass
class ModelDiscoveryConfig:
    """How to discover available models for a provider."""
    type: str  # "openai_models", "ollama_tags", "none"
    endpoint: str | None = None  # relative to base_url


@dataclass
class LLMProfile:
    """Configuration for a single LLM provider."""
    profile_id: str
    display_name: str
    provider_type: str  # "openai_compatible", "ollama"
    base_url: str
    api_key_env: str = ""  # env var name for API key
    username_env: str = ""  # env var name for username (Ollama)
    password_env: str = ""  # env var name for password (Ollama)
    default_model_env: str = ""  # env var name for default model
    default_model: str = ""  # fallback model name
    vpn_required: bool = False
    model_discovery: ModelDiscoveryConfig | None = None

    def to_dict(self, include_secrets: bool = False) -> dict[str, Any]:
        """Convert to dict, optionally excluding secret fields."""
        d = asdict(self)
        d["model_discovery"] = asdict(self.model_discovery) if self.model_discovery else None
        if not include_secrets:
            d.pop("api_key_env", None)
            d.pop("username_env", None)
            d.pop("password_env", None)
        return d


# Built-in provider profiles
BUILTIN_PROFILES = {
    "academiccloud": LLMProfile(
        profile_id="academiccloud",
        display_name="AcademicCloud",
        provider_type="openai_compatible",
        base_url="https://chat-ai.academiccloud.de/v1",
        api_key_env="ACADEMIC_CLOUD_API_KEY",
        default_model_env="ACADEMIC_CLOUD_MODEL",
        default_model="qwen3.5-397b-a17b",
        model_discovery=ModelDiscoveryConfig(
            type="openai_models",
            endpoint="/models"
        ),
    ),
    "tu_berlin_ollama": LLMProfile(
        profile_id="tu_berlin_ollama",
        display_name="TU Berlin / MLSEC Ollama",
        provider_type="ollama",
        base_url="http://gpu1.mlsec.de:11434",
        username_env="TU_BERLIN_USERNAME",
        password_env="TU_BERLIN_PASSWORD",
        api_key_env="TU_BERLIN_API_KEY",
        default_model_env="TU_BERLIN_MODEL",
        vpn_required=True,
        model_discovery=ModelDiscoveryConfig(
            type="ollama_tags",
            endpoint="/api/tags"
        ),
    ),
    "openai": LLMProfile(
        profile_id="openai",
        display_name="OpenAI",
        provider_type="openai_compatible",
        base_url="https://api.openai.com/v1",
        api_key_env="OPENAI_API_KEY",
        default_model_env="OPENAI_MODEL",
        default_model="gpt-4o-mini",
        model_discovery=ModelDiscoveryConfig(
            type="openai_models",
            endpoint="/models"
        ),
    ),
}


class EnvironmentLoader:
    """Load environment variables from external env file and project .env."""

    def __init__(self, external_env_path: str | Path, project_root: str | Path = "."):
        r"""
        Args:
            external_env_path: Path to external env folder (e.g., C:\Users\...\Personal\env)
            project_root: Project root directory
        """
        self.external_env_path = Path(external_env_path)
        self.project_root = Path(project_root).resolve()

    def load_env_files(self) -> dict[str, str]:
        """Load all environment variables from external and project .env files.

        Returns dict ready to merge with os.environ. Never logs secret values.
        """
        env = {}

        # Try external env folder (priority 1)
        for fname in [".env", "env", "env.txt"]:
            fpath = self.external_env_path / fname
            if fpath.exists():
                env.update(self._parse_env_file(fpath))
                break

        # Try project root .env.local (priority 2, overrides external)
        local_env = self.project_root / ".env.local"
        if local_env.exists():
            env.update(self._parse_env_file(local_env))

        # Try project root .env (priority 3)
        proj_env = self.project_root / ".env"
        if proj_env.exists():
            env.update(self._parse_env_file(proj_env))

        return env

    @staticmethod
    def _parse_env_file(path: Path) -> dict[str, str]:
        """Parse simple KEY=VALUE env file format."""
        out = {}
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip()
                # Remove quotes if present
                if val.startswith('"') and val.endswith('"'):
                    val = val[1:-1]
                elif val.startswith("'") and val.endswith("'"):
                    val = val[1:-1]
                out[key] = val
        except Exception:
            pass
        return out

    def build_subprocess_env(self, base_env: dict[str, str] | None = None) -> dict[str, str]:
        """Build environment dict for subprocess.Popen.

        Merges: base_env (usually os.environ.copy()) + external .env + project .env
        """
        env = dict(base_env or os.environ.copy())
        env.update(self.load_env_files())
        return env


class LLMProfileManager:
    """Manage LLM provider profiles with credential handling."""

    def __init__(self, profiles_path: str | Path | None = None,
                 env_loader: EnvironmentLoader | None = None):
        """
        Args:
            profiles_path: Path to llm_profiles.yaml (created if missing)
            env_loader: EnvironmentLoader for credential resolution
        """
        self.profiles_path = Path(profiles_path) if profiles_path else None
        self.env_loader = env_loader
        self._profiles: dict[str, LLMProfile] = {}
        self._load_profiles()

    def _load_profiles(self) -> None:
        """Load profiles from file and builtins."""
        self._profiles = dict(BUILTIN_PROFILES)

        if self.profiles_path and self.profiles_path.exists():
            try:
                data = yaml.safe_load(self.profiles_path.read_text(encoding="utf-8")) or {}
                custom = data.get("llm_profiles", {})
                for pid, pdata in custom.items():
                    if isinstance(pdata, dict):
                        md = pdata.pop("model_discovery", None)
                        model_discovery = (
                            ModelDiscoveryConfig(**md) if isinstance(md, dict) else None
                        )
                        self._profiles[pid] = LLMProfile(
                            profile_id=pid,
                            model_discovery=model_discovery,
                            **pdata
                        )
            except Exception:
                pass

    def get_profile(self, profile_id: str) -> LLMProfile | None:
        """Get a profile by ID."""
        return self._profiles.get(profile_id)

    def list_profiles(self) -> list[dict[str, Any]]:
        """List all profiles (safe for frontend, no secrets)."""
        out = []
        for pid, prof in self._profiles.items():
            d = prof.to_dict(include_secrets=False)
            # Add credential status
            if self.env_loader:
                env = self.env_loader.load_env_files()
                d["has_api_key"] = bool(prof.api_key_env and env.get(prof.api_key_env))
                d["has_username"] = bool(prof.username_env and env.get(prof.username_env))
                d["has_password"] = bool(prof.password_env and env.get(prof.password_env))
                d["selected_model"] = env.get(prof.default_model_env) or prof.default_model
            out.append(d)
        return out

    def get_credentials(self, profile_id: str) -> dict[str, str]:
        """Get credentials for a profile from environment (for use by code, not frontend)."""
        if not self.env_loader:
            return {}

        prof = self.get_profile(profile_id)
        if not prof:
            return {}

        env = self.env_loader.load_env_files()
        creds = {}

        if prof.api_key_env and prof.api_key_env in env:
            creds["api_key"] = env[prof.api_key_env]
        if prof.username_env and prof.username_env in env:
            creds["username"] = env[prof.username_env]
        if prof.password_env and prof.password_env in env:
            creds["password"] = env[prof.password_env]

        return creds

    def test_health(self, profile_id: str, timeout: float = 5.0) -> dict[str, Any]:
        """Test connectivity to a provider.

        Returns:
            {
                "ok": bool,
                "profile_id": str,
                "provider_type": str,
                "base_url": str,
                "status_code": int | None,
                "message": str,
                "vpn_required": bool,
            }
        """
        prof = self.get_profile(profile_id)
        if not prof:
            return {"ok": False, "message": f"Profile {profile_id} not found"}

        try:
            creds = self.get_credentials(profile_id)

            if prof.provider_type == "openai_compatible":
                return self._test_openai_compatible(prof, creds, timeout)
            elif prof.provider_type == "ollama":
                return self._test_ollama(prof, creds, timeout)
            else:
                return {
                    "ok": False,
                    "profile_id": profile_id,
                    "message": f"Unknown provider type: {prof.provider_type}",
                }
        except Exception as e:
            return {
                "ok": False,
                "profile_id": profile_id,
                "provider_type": prof.provider_type,
                "base_url": prof.base_url,
                "message": f"Health check failed: {str(e)}",
            }

    def _test_openai_compatible(self, prof: LLMProfile, creds: dict[str, str],
                                timeout: float) -> dict[str, Any]:
        """Test OpenAI-compatible provider."""
        headers = {"Content-Type": "application/json"}
        if creds.get("api_key"):
            headers["Authorization"] = f"Bearer {creds['api_key']}"

        url = prof.base_url.rstrip("/") + "/models"
        try:
            r = requests.get(url, headers=headers, timeout=timeout)
            ok = r.status_code == 200
            return {
                "ok": ok,
                "profile_id": prof.profile_id,
                "provider_type": prof.provider_type,
                "base_url": prof.base_url,
                "status_code": r.status_code,
                "message": "OK" if ok else f"HTTP {r.status_code}",
                "auth_present": bool(creds.get("api_key")),
            }
        except requests.exceptions.Timeout:
            return {
                "ok": False,
                "profile_id": prof.profile_id,
                "provider_type": prof.provider_type,
                "base_url": prof.base_url,
                "message": "Timeout connecting to server",
            }
        except Exception as e:
            return {
                "ok": False,
                "profile_id": prof.profile_id,
                "provider_type": prof.provider_type,
                "base_url": prof.base_url,
                "message": f"Connection failed: {str(e)}",
            }

    def _test_ollama(self, prof: LLMProfile, creds: dict[str, str],
                     timeout: float) -> dict[str, Any]:
        """Test Ollama provider."""
        headers = {}
        if creds.get("api_key"):
            headers["Authorization"] = f"Bearer {creds['api_key']}"

        url = prof.base_url.rstrip("/") + "/api/tags"
        try:
            r = requests.get(url, headers=headers, timeout=timeout)
            ok = r.status_code == 200
            return {
                "ok": ok,
                "profile_id": prof.profile_id,
                "provider_type": prof.provider_type,
                "base_url": prof.base_url,
                "status_code": r.status_code,
                "message": "OK" if ok else f"HTTP {r.status_code}",
                "vpn_required": prof.vpn_required,
            }
        except requests.exceptions.Timeout:
            return {
                "ok": False,
                "profile_id": prof.profile_id,
                "provider_type": prof.provider_type,
                "base_url": prof.base_url,
                "vpn_required": prof.vpn_required,
                "message": "Cannot reach Ollama. Check VPN connection and server URL.",
            }
        except Exception as e:
            return {
                "ok": False,
                "profile_id": prof.profile_id,
                "provider_type": prof.provider_type,
                "base_url": prof.base_url,
                "vpn_required": prof.vpn_required,
                "message": f"Connection failed: {str(e)}",
            }

    def discover_models(self, profile_id: str, timeout: float = 5.0) -> dict[str, Any]:
        """Discover available models for a provider.

        Returns:
            {
                "ok": bool,
                "profile_id": str,
                "models": [{"id": str, "display_name": str, "source": str}],
                "message": str,
            }
        """
        prof = self.get_profile(profile_id)
        if not prof or not prof.model_discovery:
            return {"ok": False, "profile_id": profile_id, "message": "No model discovery configured"}

        if prof.model_discovery.type == "openai_models":
            return self._discover_openai_models(prof, timeout)
        elif prof.model_discovery.type == "ollama_tags":
            return self._discover_ollama_models(prof, timeout)
        else:
            return {"ok": False, "profile_id": profile_id, "message": "Unknown discovery type"}

    def _discover_openai_models(self, prof: LLMProfile, timeout: float) -> dict[str, Any]:
        """Discover models from OpenAI-compatible /models endpoint (AcademicCloud, OpenAI)."""
        creds = self.get_credentials(prof.profile_id)
        headers = {}
        if creds.get("api_key"):
            headers["Authorization"] = f"Bearer {creds['api_key']}"

        endpoint = prof.model_discovery.endpoint or "/models"
        url = prof.base_url.rstrip("/") + endpoint

        try:
            r = requests.get(url, headers=headers, timeout=timeout)
            if r.status_code != 200:
                return {
                    "ok": False,
                    "profile_id": prof.profile_id,
                    "provider_type": prof.provider_type,
                    "base_url": prof.base_url,
                    "message": f"HTTP {r.status_code}: {r.text[:200]}",
                    "models": [],
                }

            data = r.json()
            models = []
            for item in data.get("data", []):
                mid = item.get("id") or item.get("model")
                if not mid:
                    continue

                model_entry: dict[str, Any] = {
                    "id": mid,
                    "display_name": item.get("name") or mid,
                    "source": "openai_models",
                    "provider": prof.profile_id,
                }

                # AcademicCloud specific fields
                if item.get("status"):
                    model_entry["status"] = item["status"]
                if "demand" in item:
                    model_entry["demand"] = item["demand"]
                if item.get("input"):
                    model_entry["input"] = item["input"]
                if item.get("output"):
                    model_entry["output"] = item["output"]
                if item.get("owned_by"):
                    model_entry["owned_by"] = item["owned_by"]
                if "created" in item:
                    model_entry["created"] = item["created"]

                models.append(model_entry)

            return {
                "ok": True,
                "profile_id": prof.profile_id,
                "provider_type": prof.provider_type,
                "base_url": prof.base_url,
                "source": "openai_models",
                "models": models,
                "message": f"Found {len(models)} model(s)",
            }
        except Exception as e:
            return {
                "ok": False,
                "profile_id": prof.profile_id,
                "provider_type": prof.provider_type,
                "base_url": prof.base_url,
                "message": f"Model discovery failed: {str(e)}",
                "models": [],
            }

    def _discover_ollama_models(self, prof: LLMProfile, timeout: float) -> dict[str, Any]:
        """Discover models from Ollama /api/tags endpoint (with /v1/models fallback)."""
        endpoint = prof.model_discovery.endpoint or "/api/tags"
        url = prof.base_url.rstrip("/") + endpoint

        try:
            r = requests.get(url, timeout=timeout)
            if r.status_code == 200:
                data = r.json()
                models = []

                # Ollama /api/tags returns {"models": [{"name": ..., "model": ..., "size": ..., "details": {...}}]}
                for item in data.get("models", []):
                    mid = item.get("model") or item.get("name")
                    if not mid:
                        continue

                    # Convert size bytes to GB
                    size_bytes = item.get("size", 0)
                    size_gb = round(size_bytes / (1024**3), 2) if size_bytes else 0

                    model_entry: dict[str, Any] = {
                        "id": mid,
                        "display_name": item.get("name") or mid,
                        "source": "ollama_tags",
                        "provider": prof.profile_id,
                    }

                    # Ollama specific fields
                    if item.get("modified_at"):
                        model_entry["modified_at"] = item["modified_at"]
                    if size_bytes:
                        model_entry["size_bytes"] = size_bytes
                        model_entry["size_gb"] = size_gb
                    if item.get("digest"):
                        model_entry["digest"] = item["digest"]

                    # Details nested object
                    details = item.get("details", {})
                    if details.get("family"):
                        model_entry["family"] = details["family"]
                    if details.get("families"):
                        model_entry["families"] = details["families"]
                    if details.get("parameter_size"):
                        model_entry["parameter_size"] = details["parameter_size"]
                    if details.get("quantization_level"):
                        model_entry["quantization_level"] = details["quantization_level"]
                    if details.get("format"):
                        model_entry["format"] = details["format"]

                    models.append(model_entry)

                return {
                    "ok": True,
                    "profile_id": prof.profile_id,
                    "provider_type": prof.provider_type,
                    "base_url": prof.base_url,
                    "source": "ollama_tags",
                    "models": models,
                    "message": f"Found {len(models)} model(s)",
                }

            # Fallback to /v1/models if /api/tags fails
            if r.status_code >= 400:
                url_v1 = prof.base_url.rstrip("/") + "/v1/models"
                r_v1 = requests.get(url_v1, timeout=timeout)
                if r_v1.status_code == 200:
                    return self._parse_openai_models_response(prof, r_v1.json())

            return {
                "ok": False,
                "profile_id": prof.profile_id,
                "provider_type": prof.provider_type,
                "base_url": prof.base_url,
                "vpn_required": prof.vpn_required,
                "message": f"HTTP {r.status_code}: Ollama unreachable. Check VPN connection.",
                "models": [],
            }
        except requests.exceptions.Timeout:
            return {
                "ok": False,
                "profile_id": prof.profile_id,
                "provider_type": prof.provider_type,
                "base_url": prof.base_url,
                "vpn_required": prof.vpn_required,
                "message": "Timeout: Cannot reach Ollama. Check VPN connection.",
                "models": [],
            }
        except Exception as e:
            return {
                "ok": False,
                "profile_id": prof.profile_id,
                "provider_type": prof.provider_type,
                "base_url": prof.base_url,
                "vpn_required": prof.vpn_required,
                "message": f"Model discovery failed: {str(e)}",
                "models": [],
            }

    @staticmethod
    def _parse_openai_models_response(prof: LLMProfile, data: dict[str, Any]) -> dict[str, Any]:
        """Helper to parse OpenAI /models response (fallback for Ollama /v1/models)."""
        models = []
        for item in data.get("data", []):
            mid = item.get("id") or item.get("model")
            if not mid:
                continue
            model_entry: dict[str, Any] = {
                "id": mid,
                "display_name": item.get("name") or mid,
                "source": "openai_models",
                "provider": prof.profile_id,
            }
            if item.get("status"):
                model_entry["status"] = item["status"]
            if item.get("owned_by"):
                model_entry["owned_by"] = item["owned_by"]
            models.append(model_entry)
        return {
            "ok": True,
            "profile_id": prof.profile_id,
            "provider_type": prof.provider_type,
            "base_url": prof.base_url,
            "source": "openai_models",
            "models": models,
            "message": f"Found {len(models)} model(s)",
        }
