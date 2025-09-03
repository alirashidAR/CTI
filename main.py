from fastapi import FastAPI, HTTPException
import requests
import ipaddress
import re
from urllib.parse import urlparse
from typing import Dict, Any
from dotenv import load_dotenv
import os
from gemini import summary


load_dotenv()  # Load environment variables from .env file

OTX_API_KEY = os.getenv("OTX_API_KEY")

# Replace with your OTX API key (move this to env var in production!)
# OTX_API_KEY = "your_api_key_here"
BASE_URL = "https://otx.alienvault.com/api/v1"
HEADERS = {"X-OTX-API-KEY": OTX_API_KEY}

app = FastAPI(
    title="OTX CTI Hub - GET-only",
    description="Get complete threat intelligence for IPs, file hashes, domains, and URLs"
)

# ----------------- Helpers -----------------
def fetch_from_otx(endpoint: str) -> Dict[Any, Any]:
    """Fetch data from OTX API"""
    url = f"{BASE_URL}/{endpoint}"
    try:
        response = requests.get(url, headers=HEADERS, timeout=30)
        if response.status_code == 404:
            return {"error": "No data found for this indicator"}
        elif response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"OTX API error: {response.text}"
            )
        return response.json()
    except requests.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Request failed: {str(e)}")


def is_valid_ip(ip: str) -> tuple[bool, str]:
    """Check if IP is valid and return IP type"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return True, "IPv6" if ip_obj.version == 6 else "IPv4"
    except ValueError:
        return False, ""


def is_valid_domain(domain: str) -> bool:
    """Check if domain is valid format"""
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    return bool(domain_pattern.match(domain))


def is_valid_url(url: str) -> bool:
    """Check if URL is valid format"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False


# ----------------- Fetch per type -----------------
def get_all_ip_data(ip: str, ip_type: str) -> Dict[Any, Any]:
    sections = ["general", "malware", "url_list"]
    return {s: fetch_from_otx(f"indicators/{ip_type}/{ip}/{s}") for s in sections}


def get_all_file_data(file_hash: str) -> Dict[Any, Any]:
    sections = ["general"]
    return {s: fetch_from_otx(f"indicators/file/{file_hash}/{s}") for s in sections}


def get_all_domain_data(domain: str) -> Dict[Any, Any]:
    sections = ["general", "malware", "url_list"]
    return {s: fetch_from_otx(f"indicators/domain/{domain}/{s}") for s in sections}


def get_all_url_data(url: str) -> Dict[Any, Any]:
    sections = ["general", "url_list"]
    return {s: fetch_from_otx(f"indicators/url/{url}/{s}") for s in sections}


# ----------------- API Endpoints -----------------
@app.get("/")
def root():
    return {
        "message": "OTX CTI Hub - GET-only API",
        "supported_indicators": ["IP addresses", "File hashes", "Domains", "URLs"],
        "endpoints": {
            "ip_analysis": "/analyze/ip/{ip_address}",
            "file_analysis": "/analyze/file/{file_hash}",
            "domain_analysis": "/analyze/domain/{domain}",
            "url_analysis": "/analyze/url/{url}",
            "smart_lookup": "/lookup/{indicator} (auto-detects type)",
            "bulk_lookup": "/analyze/bulk?indicators=comma,separated,list"
        }
    }


@app.get("/analyze/ip/{ip_address}")
def analyze_ip(ip_address: str):
    """Analyze an IP address"""
    is_valid, ip_type = is_valid_ip(ip_address)
    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    return {
        "indicator": ip_address,
        "indicator_type": ip_type,
        "data": get_all_ip_data(ip_address, ip_type)
    }


@app.get("/analyze/file/{file_hash}")
def analyze_file(file_hash: str):
    """Analyze a file hash"""
    if not file_hash or len(file_hash) < 32:
        raise HTTPException(status_code=400, detail="Invalid file hash format")
    return {
        "indicator": file_hash,
        "indicator_type": "file_hash",
        "data": get_all_file_data(file_hash)
    }


@app.get("/analyze/domain/{domain}")
def analyze_domain(domain: str):
    """Analyze a domain"""
    domain = domain.strip().lower()
    if not is_valid_domain(domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")
    return {
        "indicator": domain,
        "indicator_type": "domain",
        "data": get_all_domain_data(domain)
    }


@app.get("/analyze/url/{url:path}")
def analyze_url(url: str):
    """Analyze a URL"""
    if not is_valid_url(url):
        raise HTTPException(status_code=400, detail="Invalid URL format")
    return {
        "indicator": url,
        "indicator_type": "url",
        "data": get_all_url_data(url)
    }


@app.get("/lookup/{indicator:path}")
def quick_lookup(indicator: str):
    """Smart lookup (auto-detects type: IP, Domain, URL, File hash)"""
    indicator = indicator.strip()

    # IP
    is_valid_ip_result, ip_type = is_valid_ip(indicator)
    if is_valid_ip_result:
        return {
            "indicator": indicator,
            "indicator_type": ip_type,
            "detected_as": "IP address",
            "data": get_all_ip_data(indicator, ip_type)
        }

    # URL
    if is_valid_url(indicator):
        return {
            "indicator": indicator,
            "indicator_type": "url",
            "detected_as": "URL",
            "data": get_all_url_data(indicator)
        }

    # Domain
    if is_valid_domain(indicator):
        return {
            "indicator": indicator,
            "indicator_type": "domain",
            "detected_as": "Domain",
            "data": get_all_domain_data(indicator)
        }

    # File hash
    if len(indicator) >= 32 and all(c in '0123456789abcdefABCDEF' for c in indicator):
        return {
            "indicator": indicator,
            "indicator_type": "file_hash",
            "detected_as": "File hash",
            "data": get_all_file_data(indicator)
        }

    raise HTTPException(
        status_code=400,
        detail="Invalid indicator. Must be a valid IP, domain, URL, or file hash"
    )


@app.get("/analyze/bulk")
def analyze_bulk(indicators: str):
    """
    Bulk analyze (comma-separated list, max 10).
    Example: /analyze/bulk?indicators=8.8.8.8,example.com,http://test.com
    """
    items = [i.strip() for i in indicators.split(",") if i.strip()]
    if len(items) > 10:
        raise HTTPException(status_code=400, detail="Maximum 10 indicators allowed per request")

    results = []
    for i in items:
        try:
            results.append(quick_lookup(i))
        except HTTPException as e:
            results.append({"indicator": i, "error": e.detail})

    return {"results": results}
