from fastapi import FastAPI, HTTPException, Query
import requests, ipaddress, re, os, hashlib
from urllib.parse import urlparse
from typing import Dict, Any
from dotenv import load_dotenv
from gemini import summary
import uvicorn

load_dotenv()

# ===================== API KEYS =====================
OTX_API_KEY = os.getenv("OTX_API_KEY")
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not OTX_API_KEY or not VT_API_KEY or not GEMINI_API_KEY:
    raise RuntimeError("Please set OTX_API_KEY, VIRUSTOTAL_API_KEY, GEMINI_API_KEY in .env")

# ===================== BASE CONFIG =====================
BASE_OTX = "https://otx.alienvault.com/api/v1"
HEADERS_OTX = {"X-OTX-API-KEY": OTX_API_KEY}

BASE_VT = "https://www.virustotal.com/api/v3"
HEADERS_VT = {"accept": "application/json", "x-apikey": VT_API_KEY}

# ===================== FASTAPI =====================
app = FastAPI(
    title="Federated CTI Hub",
    description="Enrich indicators with OTX + VirusTotal + Optional Summarization",
    version="1.0"
)

# ===================== HELPERS =====================
def fetch_otx(endpoint: str) -> Dict[Any, Any]:
    url = f"{BASE_OTX}/{endpoint}"
    try:
        r = requests.get(url, headers=HEADERS_OTX, timeout=30)
        if r.status_code == 404:
            return {"error": "No OTX data"}
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": f"OTX error: {str(e)}"}

def fetch_vt(endpoint: str) -> Dict[Any, Any]:
    url = f"{BASE_VT}/{endpoint}"
    try:
        r = requests.get(url, headers=HEADERS_VT, timeout=30)
        if r.status_code == 404:
            return {"error": "No VT data"}
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": f"VT error: {str(e)}"}

def is_valid_ip(ip: str) -> tuple[bool, str]:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return True, "IPv6" if ip_obj.version == 6 else "IPv4"
    except ValueError:
        return False, ""

def is_valid_domain(domain: str) -> bool:
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    return bool(domain_pattern.match(domain))

def is_valid_url(url: str) -> bool:
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def detect_hash_type(h: str) -> str | None:
    h = h.lower()
    if re.fullmatch(r"[a-f0-9]{32}", h):
        return "MD5"
    elif re.fullmatch(r"[a-f0-9]{40}", h):
        return "SHA1"
    elif re.fullmatch(r"[a-f0-9]{64}", h):
        return "SHA256"
    return None

# ===================== FEDERATED LOOKUP =====================
@app.get("/federated/{indicator:path}")
async def federated_lookup(indicator: str, summarize: bool = Query(False, description="Set true to add Gemini summary")):
    """
    Federated lookup across OTX + VirusTotal.
    Auto-detects indicator type (IP, Domain, URL, File hash).
    Optional summarization via ?summarize=true.
    """
    indicator = indicator.strip()

    result = {
        "indicator": indicator,
        "indicator_type": None,
        "sources": {}
    }

    # ---- IP ----
    is_ip, ip_type = is_valid_ip(indicator)
    if is_ip:
        result["indicator_type"] = ip_type
        result["sources"] = {
            "otx": {
                "general": fetch_otx(f"indicators/{ip_type}/{indicator}/general"),
                "malware": fetch_otx(f"indicators/{ip_type}/{indicator}/malware"),
                "url_list": fetch_otx(f"indicators/{ip_type}/{indicator}/url_list"),
            },
            "virustotal": fetch_vt(f"ip_addresses/{indicator}")
        }

    # ---- URL ----
    elif is_valid_url(indicator):
        result["indicator_type"] = "url"
        result["sources"] = {
            "otx": {
                "general": fetch_otx(f"indicators/url/{indicator}/general"),
                "url_list": fetch_otx(f"indicators/url/{indicator}/url_list"),
            },
            "virustotal": fetch_vt(f"urls/{indicator}")
        }

    # ---- Domain ----
    elif is_valid_domain(indicator):
        result["indicator_type"] = "domain"
        result["sources"] = {
            "otx": {
                "general": fetch_otx(f"indicators/domain/{indicator}/general"),
                "malware": fetch_otx(f"indicators/domain/{indicator}/malware"),
            },
            "virustotal": fetch_vt(f"domains/{indicator}")
        }

    # ---- File Hash ----
    else:
        hash_type = detect_hash_type(indicator)
        if hash_type:
            result["indicator_type"] = f"file_hash ({hash_type})"
            result["sources"] = {
                "otx": {
                    "general": fetch_otx(f"indicators/file/{indicator}/general"),
                    "analysis": fetch_otx(f"indicators/file/{indicator}/analysis"),
                },
                "virustotal": fetch_vt(f"files/{indicator}")
            }
        else:
            raise HTTPException(
                status_code=400,
                detail="Invalid indicator. Must be IP, domain, URL, or file hash"
            )

    # ---- Optional Summarization ----
    if summarize:
        vt_context = str(result["sources"].get("virustotal", {}))
        otx_context = str(result["sources"].get("otx", {}))

        # Split the 15k limit between VT and OTX
        max_len = 15000
        half_len = max_len // 2

        vt_trimmed = vt_context[:half_len]
        otx_trimmed = otx_context[:half_len]

        combined_context = f"VirusTotal:\n{vt_trimmed}\n\nOTX:\n{otx_trimmed}"

        result["summary"] = await summary(combined_context)

        return {
            "summary": result["summary"]
        }


    return result


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)