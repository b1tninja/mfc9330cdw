"""XML request builders matching CBrInet::VerCheck / CBrInet::FileUpdate."""

from __future__ import annotations

from dataclasses import dataclass, field
from xml.etree import ElementTree as ET


# Defaults from res/BrUpdSys.xml (tool 4.9.05 / BrMain4905)
DEFAULT_OS = "WIN_NATIVE"
DEFAULT_AREA = "ALL"
DEFAULT_CATEGORY = "MAIN"
DEFAULT_TOOL_OSVERSION = "0"  # string form used by VerCheck (<OSVERSION>%s>)

# Model names as returned by verCheck RESISTINFO for this product
MODEL_LAN = "Brother MFC-9330CDW Printer"
MODEL_USB = "Brother MFC-9330CDW USB Printer"

# fileUpdate NAME that the vendor server accepts for this product (not the
# Windows driver string). SPEC 0401 is the documented US/EU regional code.
MODEL_FIRMVERUP = "MFC-9330CDW"
DEFAULT_SPEC = "0401"
DEFAULT_DRIVER = "EWS"

# Categories that currently return a PATH for MFC-9330CDW / SPEC 0401
FIRM_CATEGORIES = (
    "MAIN",
    "PCLPS",
    "ENGINE",
    "SUB1",
    "SUB2",
    "SUB3",
    "SUB4",
    "SUB5",
    "BRNET",
    "IFAX",
)

# Known-working low versions that force VERSIONCHECK=0 + PATH
DEFAULT_FIRM_VERSIONS = {
    "MAIN": "R1506121801:4504",
    "SUB1": "1.00",
    "SUB2": "L1505291600",
    "IFAX": "0",
}


@dataclass
class FirmSlot:
    firm_id: str = "MAIN"
    version: str = "0"


@dataclass
class VerCheckParams:
    model_name: str = MODEL_LAN
    firm_category: str = DEFAULT_CATEGORY
    os_name: str = DEFAULT_OS
    os_version: str = DEFAULT_TOOL_OSVERSION  # string
    area: str = DEFAULT_AREA
    inspect_mode: int = 0
    include_model: bool = True


@dataclass
class FileUpdateParams:
    """Shape recovered from FileUpdate AppendFormat + live vendor captures.

    Working combo for MFC-9330CDW: NAME=MFC-9330CDW, SPEC=0401, DRIVER=EWS,
    a real-looking VERSION (not bare \"0\"/\"1\"), User-Agent BrHttpc/1.00.
    VERSIONCHECK: 0=update+PATH, 1=current, 2=rejected model/SPEC/context.
    """

    model_name: str = MODEL_FIRMVERUP
    firm_category: str = DEFAULT_CATEGORY
    os_name: str = DEFAULT_OS
    os_version: int | None = None  # Windows tool sends this; BrHttpc captures omit it
    inspect_mode: int = 0
    serial_no: str | None = None  # None => omit SELIALNO (BrHttpc style)
    spec: str = DEFAULT_SPEC
    driver: str = DEFAULT_DRIVER
    firms: list[FirmSlot] = field(default_factory=lambda: [FirmSlot(version="R1506121801:4504")])
    driver_cnt: int | None = None  # None => count non-empty driver slots
    log_no: str = "2"  # literal default compared in FileUpdate
    err_bit: str | None = None  # None => omit ERRBIT
    need_response: int = 1  # 1=XML metadata, 0=octet-stream body (often empty if VC!=ok)
    include_os_version: bool = False


def _txt(parent: ET.Element, tag: str, text: str | int | None = None) -> ET.Element:
    el = ET.SubElement(parent, tag)
    if text is not None:
        el.text = str(text)
    return el


def build_ver_check_request(p: VerCheckParams | None = None) -> str:
    """POST body for .../ifax2.asmx/verCheck (UTF-8, Content-Type: text/xml)."""
    p = p or VerCheckParams()
    root = ET.Element("REQUESTINFO")
    tool = _txt(root, "FIRMUPDATETOOLINFO")
    _txt(tool, "FIRMCATEGORY", p.firm_category)
    _txt(tool, "OS", p.os_name)
    _txt(tool, "OSVERSION", p.os_version)
    _txt(tool, "AREA", p.area)
    _txt(tool, "INSPECTMODE", p.inspect_mode)
    if p.include_model:
        upd = _txt(root, "FIRMUPDATEINFO")
        model = _txt(upd, "MODELINFO")
        _txt(model, "NAME", p.model_name)
    return ET.tostring(root, encoding="unicode")


def build_file_update_request(p: FileUpdateParams | None = None) -> str:
    """POST body for .../ifax2.asmx/fileUpdate.

    Nesting follows the FileUpdate push order: SELIALNO/NAME/SPEC/DRIVER/FIRMINFO
    live under MODELINFO; DRIVERCNT/LOGNO/ERRBIT/NEEDRESPONSE under FIRMUPDATEINFO.
    """
    p = p or FileUpdateParams()
    root = ET.Element("REQUESTINFO")
    tool = _txt(root, "FIRMUPDATETOOLINFO")
    # FIRM category is reported as MAIN in FIRMCATEGORY (oh-brother / verCheck)
    tool_cat = "MAIN" if p.firm_category == "FIRM" else p.firm_category
    _txt(tool, "FIRMCATEGORY", tool_cat)
    _txt(tool, "OS", p.os_name)
    if p.include_os_version and p.os_version is not None:
        _txt(tool, "OSVERSION", p.os_version)
    _txt(tool, "INSPECTMODE", p.inspect_mode)

    upd = _txt(root, "FIRMUPDATEINFO")
    model = _txt(upd, "MODELINFO")
    if p.serial_no is not None:
        _txt(model, "SELIALNO", p.serial_no)
    _txt(model, "NAME", p.model_name)
    _txt(model, "SPEC", p.spec)
    _txt(model, "DRIVER", p.driver)

    firm_info = _txt(model, "FIRMINFO")
    for slot in p.firms:
        firm = _txt(firm_info, "FIRM")
        # IFAX firm slot uses ID MAIN when requesting IFAX category
        firm_id = "MAIN" if slot.firm_id == "IFAX" else slot.firm_id
        _txt(firm, "ID", firm_id)
        _txt(firm, "VERSION", slot.version)

    driver_cnt = p.driver_cnt
    if driver_cnt is None:
        driver_cnt = 1 if p.driver else 0
    _txt(upd, "DRIVERCNT", driver_cnt)
    _txt(upd, "LOGNO", p.log_no)
    if p.err_bit is not None:
        _txt(upd, "ERRBIT", p.err_bit)
    _txt(upd, "NEEDRESPONSE", p.need_response)
    return ET.tostring(root, encoding="unicode")


def parse_response_xml(data: bytes | str) -> ET.Element:
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace")
    return ET.fromstring(data)


def xpath_text(root: ET.Element, path: str) -> str | None:
    """Simple slash path from root, e.g. RESPONSEINFO/FIRMUPDATEINFO/VERSIONCHECK."""
    node: ET.Element | None = root
    for part in path.strip("/").split("/"):
        if node is None:
            return None
        node = node.find(part)
    return None if node is None else (node.text or "")


def _response_root(root: ET.Element) -> ET.Element:
    """Accept either <RESPONSEINFO>… or a document already rooted there."""
    if root.tag == "RESPONSEINFO":
        return root
    child = root.find("RESPONSEINFO")
    return child if child is not None else root


def summarize_ver_check(root: ET.Element) -> dict:
    resp = _response_root(root)
    models = [n.text or "" for n in resp.findall(".//MODELINFO/MODEL/NAME")]
    firm_ids = [n.text or "" for n in resp.findall(".//FIRMINFO/FIRM/ID")]
    marks = {
        f"MARK{i}": xpath_text(resp, f"RESISTINFO/MODELINFO/MARK{i}") for i in range(1, 8)
    }
    return {
        "tool_version": xpath_text(resp, "FIRMUPDATETOOLINFO/VERSION"),
        "password": xpath_text(resp, "FIRMUPDATETOOLINFO/PASSWORD"),
        "model_count": len(models),
        "models_matching_9330": [m for m in models if "9330" in (m or "")],
        "firm_ids": firm_ids,
        "marks": marks,
    }


def summarize_file_update(root: ET.Element) -> dict:
    resp = _response_root(root)
    info = resp.find("FIRMUPDATEINFO")
    base = info if info is not None else resp
    keys = (
        "VERSIONCHECK",
        "MEMORYVERSION",
        "FIRMID",
        "PATH",
        "LATESTVERSION",
        "DLTIME",
    )
    return {k: base.findtext(k) for k in keys}
