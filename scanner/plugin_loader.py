"""Plugin loader for external check modules under plugins/ directories."""
from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Callable, Dict, List, Tuple

import yaml


def load_plugins(plugins_dir: str) -> tuple[Dict[str, Callable], List[str]]:
    """Load plugin checks from plugin.yaml + plugin.py pairs.

    plugin.yaml schema (minimal):
      id: string
      entrypoint: plugin.py
      function: run
    """
    root = Path(plugins_dir)
    if not root.exists() or not root.is_dir():
        return {}, []

    loaded: Dict[str, Callable] = {}
    notes: List[str] = []

    for child in root.iterdir():
        if not child.is_dir():
            continue
        manifest = child / "plugin.yaml"
        if not manifest.exists():
            continue

        try:
            with manifest.open("r", encoding="utf-8") as f:
                meta = yaml.safe_load(f) or {}
        except Exception as e:
            notes.append(f"plugin '{child.name}' skipped: invalid plugin.yaml ({e})")
            continue

        plugin_id = (meta.get("id") or child.name).strip()
        entry = (meta.get("entrypoint") or "plugin.py").strip()
        fn_name = (meta.get("function") or "run").strip()

        module_path = child / entry
        if not module_path.exists():
            notes.append(f"plugin '{plugin_id}' skipped: missing entrypoint {entry}")
            continue

        try:
            spec = importlib.util.spec_from_file_location(f"scanner_plugin_{plugin_id}", module_path)
            if spec is None or spec.loader is None:
                raise RuntimeError("could not build module spec")
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            fn = getattr(mod, fn_name)
            if not callable(fn):
                raise TypeError(f"{fn_name} is not callable")
            loaded[plugin_id] = fn
            notes.append(f"plugin '{plugin_id}' loaded")
        except Exception as e:
            notes.append(f"plugin '{plugin_id}' skipped: {e}")

    return loaded, notes


def list_plugin_ids(plugins_dir: str) -> List[str]:
    loaded, _ = load_plugins(plugins_dir)
    return sorted(loaded.keys())
