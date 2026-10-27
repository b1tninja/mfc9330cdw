"""CLI: python -m tools.firmverup …  (run from repo root with PYTHONPATH=.)"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .client import FirmverupClient
from .protocol import (
    DEFAULT_DRIVER,
    DEFAULT_FIRM_VERSIONS,
    DEFAULT_SPEC,
    FIRM_CATEGORIES,
    MODEL_FIRMVERUP,
    MODEL_LAN,
    MODEL_USB,
    FileUpdateParams,
    FirmSlot,
    VerCheckParams,
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _default_out_dir() -> Path:
    return _repo_root() / "downloads" / "firmware" / "meta"


def cmd_ver_check(args: argparse.Namespace) -> int:
    client = FirmverupClient(timeout=args.timeout)
    params = VerCheckParams(
        model_name=args.model,
        firm_category=args.category,
        inspect_mode=args.inspect_mode,
        include_model=not args.no_model,
    )
    result = client.ver_check(params)
    out = Path(args.out) if args.out else _default_out_dir() / "verCheck-latest.xml"
    client.save_raw(result, out)
    print(json.dumps(result["summary"], indent=2))
    print(f"saved {out} ({result['byte_length'] if 'byte_length' in result else len(result['raw'])} bytes)", file=sys.stderr)
    return 0


def cmd_file_update(args: argparse.Namespace) -> int:
    client = FirmverupClient(timeout=args.timeout)
    firm_id = args.firm_id or args.category
    firm_version = args.firm_version or DEFAULT_FIRM_VERSIONS.get(firm_id, "0")
    params = FileUpdateParams(
        model_name=args.model,
        firm_category=args.category,
        os_version=args.os_version,
        include_os_version=args.include_os_version,
        inspect_mode=args.inspect_mode,
        serial_no=args.serial if args.serial is not None else None,
        spec=args.spec,
        driver=args.driver,
        firms=[FirmSlot(firm_id=firm_id, version=firm_version)],
        log_no=args.log_no,
        err_bit=args.err_bit,
        need_response=args.need_response,
    )
    if args.print_request:
        from .protocol import build_file_update_request

        print(build_file_update_request(params))
        if not args.send:
            return 0

    result = client.file_update(params)
    suffix = "xml" if result["kind"] == "xml" else "bin"
    out = (
        Path(args.out)
        if args.out
        else _default_out_dir()
        / f"fileUpdate-{args.category}-{args.firm_id}-nr{args.need_response}.{suffix}"
    )
    client.save_raw(result, out)
    payload = {
        "kind": result["kind"],
        "content_type": result["content_type"],
        "byte_length": result["byte_length"],
        "summary": result["summary"],
        "request_xml": result["request_xml"] if args.verbose else None,
    }
    print(json.dumps({k: v for k, v in payload.items() if v is not None}, indent=2))
    print(f"saved {out}", file=sys.stderr)
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    """Sweep a few request shapes and print VERSIONCHECK codes."""
    client = FirmverupClient(timeout=args.timeout)
    models = [args.model] if args.model else [MODEL_FIRMVERUP, MODEL_LAN, MODEL_USB]
    categories = [args.category] if args.category else list(FIRM_CATEGORIES)
    rows = []
    for model in models:
        for cat in categories:
            ver = args.firm_version or DEFAULT_FIRM_VERSIONS.get(cat, "0")
            params = FileUpdateParams(
                model_name=model,
                firm_category=cat,
                spec=args.spec,
                driver=args.driver,
                firms=[FirmSlot(firm_id=cat, version=ver)],
                need_response=1,
                serial_no=args.serial if args.serial else None,
            )
            try:
                result = client.file_update(params)
                summary = result.get("summary") or {}
                rows.append(
                    {
                        "model": model,
                        "category": cat,
                        "firm_version": ver,
                        "kind": result["kind"],
                        "bytes": result["byte_length"],
                        "VERSIONCHECK": summary.get("VERSIONCHECK"),
                        "PATH": summary.get("PATH"),
                        "LATESTVERSION": summary.get("LATESTVERSION"),
                    }
                )
            except Exception as exc:  # noqa: BLE001 — probe should continue
                rows.append({"model": model, "category": cat, "error": str(exc)})
    print(json.dumps(rows, indent=2))
    return 0


def cmd_download_all(args: argparse.Namespace) -> int:
    """Query every firm category and download unique PATH blobs."""
    client = FirmverupClient(timeout=args.timeout)
    out_dir = Path(args.out) if args.out else _repo_root() / "downloads" / "firmware" / "blobs"
    out_dir.mkdir(parents=True, exist_ok=True)
    inventory: list[dict] = []
    seen_urls: set[str] = set()

    for cat in FIRM_CATEGORIES:
        ver = DEFAULT_FIRM_VERSIONS.get(cat, args.firm_version)
        params = FileUpdateParams(
            model_name=args.model,
            firm_category=cat,
            spec=args.spec,
            driver=args.driver,
            firms=[FirmSlot(firm_id=cat, version=ver)],
            inspect_mode=args.inspect_mode,
        )
        result = client.file_update(params)
        summary = result.get("summary") or {}
        xml_path = out_dir / f"fileUpdate-{cat}.xml"
        client.save_raw(result, xml_path)
        entry = {
            "category": cat,
            "firm_version_sent": ver,
            "VERSIONCHECK": summary.get("VERSIONCHECK"),
            "LATESTVERSION": summary.get("LATESTVERSION"),
            "PATH": summary.get("PATH"),
            "FIRMID": summary.get("FIRMID"),
            "response_xml": str(xml_path),
        }
        path_url = summary.get("PATH")
        if path_url and path_url not in seen_urls:
            seen_urls.add(path_url)
            fname = path_url.rstrip("/").rsplit("/", 1)[-1]
            dest = out_dir / fname
            if not args.skip_existing or not dest.exists():
                client.download_path(path_url, dest)
            entry["local_file"] = str(dest)
            entry["local_bytes"] = dest.stat().st_size if dest.exists() else 0
            (out_dir / f"{fname}.meta.txt").write_text(
                "\n".join(
                    f"{k}={v}"
                    for k, v in {
                        "category": cat,
                        "latest": summary.get("LATESTVERSION"),
                        "url": path_url,
                        "size": entry.get("local_bytes"),
                    }.items()
                )
                + "\n",
                encoding="utf-8",
            )
        inventory.append(entry)
        print(
            f"{cat:8} VC={entry['VERSIONCHECK']} "
            f"LATEST={entry['LATESTVERSION']} PATH={entry['PATH']}",
            file=sys.stderr,
        )

    inv_path = out_dir / "inventory.json"
    inv_path.write_text(json.dumps(inventory, indent=2), encoding="utf-8")
    print(json.dumps({"out_dir": str(out_dir), "inventory": inventory}, indent=2))
    print(f"wrote {inv_path}", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="firmverup",
        description="Brother firmverup client (FirmwareUpdater.exe protocol)",
    )
    p.add_argument("--timeout", type=float, default=60.0)
    sub = p.add_subparsers(dest="cmd", required=True)

    vc = sub.add_parser("ver-check", help="POST verCheck (model catalog / marks)")
    vc.add_argument("--model", default=MODEL_LAN)
    vc.add_argument("--category", default="MAIN", choices=FIRM_CATEGORIES)
    vc.add_argument("--inspect-mode", type=int, default=0)
    vc.add_argument("--no-model", action="store_true")
    vc.add_argument("--out", type=Path)
    vc.set_defaults(func=cmd_ver_check)

    fu = sub.add_parser("file-update", help="POST fileUpdate (firmware path / blob)")
    fu.add_argument("--model", default=MODEL_FIRMVERUP)
    fu.add_argument("--category", default="MAIN", choices=FIRM_CATEGORIES)
    fu.add_argument("--firm-id", default="")
    fu.add_argument("--firm-version", default="")
    fu.add_argument("--os-version", type=int, default=10)
    fu.add_argument(
        "--include-os-version",
        action="store_true",
        help="emit OSVERSION (Windows updater); omitted by default to match BrHttpc",
    )
    fu.add_argument("--inspect-mode", type=int, default=0)
    fu.add_argument("--serial", default=None)
    fu.add_argument("--spec", default=DEFAULT_SPEC)
    fu.add_argument("--driver", default=DEFAULT_DRIVER)
    fu.add_argument("--log-no", default="2")
    fu.add_argument("--err-bit", default=None)
    fu.add_argument("--need-response", type=int, default=1, choices=(0, 1))
    fu.add_argument("--print-request", action="store_true")
    fu.add_argument("--send", action="store_true", help="with --print-request, also POST")
    fu.add_argument("--out", type=Path)
    fu.add_argument("-v", "--verbose", action="store_true")
    fu.set_defaults(func=cmd_file_update)

    pr = sub.add_parser("probe", help="Sweep categories; print VERSIONCHECK matrix")
    pr.add_argument("--model", default="")
    pr.add_argument("--category", default="", help="limit to one category")
    pr.add_argument("--firm-version", default="")
    pr.add_argument("--spec", default=DEFAULT_SPEC)
    pr.add_argument("--driver", default=DEFAULT_DRIVER)
    pr.add_argument("--serial", default="")
    pr.set_defaults(func=cmd_probe)

    dl = sub.add_parser("download-all", help="Download all available firm category blobs")
    dl.add_argument("--model", default=MODEL_FIRMVERUP)
    dl.add_argument("--spec", default=DEFAULT_SPEC)
    dl.add_argument("--driver", default=DEFAULT_DRIVER)
    dl.add_argument("--firm-version", default="0", help="fallback version for unknown cats")
    dl.add_argument("--inspect-mode", type=int, default=0)
    dl.add_argument("--out", type=Path)
    dl.add_argument("--skip-existing", action="store_true")
    dl.set_defaults(func=cmd_download_all)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
