import requests
import json

API_KEY = 
BASE_URL = "https://malshare.com/api.php"

def get(endpoint, **params):
    params["api_key"] = API_KEY
    params["action"] = endpoint
    response = requests.get(BASE_URL, params=params)
    if response.status_code == 200:
        try:
            return response.json()
        except:
            return response.text
    else:
        print(f"[ERROR] {response.status_code}")
        return None

def get_recent_hashes():
    return get("getlist")

def get_sources():
    return get("getsources")

def get_file_types():
    return get("gettypes")

def get_file_names():
    return get("getfilenames")

def get_file_details(md5_hash):
    return get("details", hash=md5_hash)

def summarize_iocs():
    hashes = get_recent_hashes()
    sources = get_sources()
    types = get_file_types()
    filenames = get_file_names()

    print("== IoCs from MalShare (last 24 hrs) ==")
    print(f"Total Hashes: {len(hashes)}\n")
    for i, h in enumerate(hashes[:10]):  
        details = get_file_details(h)
        print(f"[{i+1}] Hash: {h}")
        if isinstance(details, dict):
            print(f"  Type     : {details.get('TYPE')}")
            print(f"  Size     : {details.get('SIZE')} bytes")
            print(f"  First Seen: {details.get('FIRST_SEEN')}")
        else:
            print("  Details unavailable.")
        print("-" * 40)

    print("\n== Sources ==")
    print(json.dumps(sources, indent=2))

    print("\n== File Types ==")
    print(json.dumps(types, indent=2))

    print("\n== Filenames ==")
    print(filenames[:10])  # Just print first 10 for brevity

if __name__ == "__main__":
    summarize_iocs()

