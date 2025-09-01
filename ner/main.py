from google import genai
from google.genai import types
import os
from dotenv import load_dotenv

load_dotenv()
os.environ["GEMINI_API_KEY"] = os.getenv("GEMINI_API_KEY")

# Define the token schema explicitly
token_schema = types.Schema(
    type="object",
    properties={
        "token": types.Schema(type="string"),
        "label": types.Schema(
            type="string",
            enum=[
                "B-ACT","I-ACT","E-ACT","S-ACT",
                "B-APT","I-APT","E-APT","S-APT",
                "B-DOM","I-DOM","E-DOM","S-DOM",
                "B-EMAIL","E-EMAIL","S-EMAIL",
                "B-ENCR","I-ENCR","E-ENCR","S-ENCR",
                "B-FILE","I-FILE","E-FILE","S-FILE",
                "B-IDTY","I-IDTY","E-IDTY","S-IDTY",
                "B-IP","I-IP","E-IP","S-IP",
                "B-LOC","I-LOC","E-LOC","S-LOC",
                "B-MAL","I-MAL","E-MAL","S-MAL",
                "B-OS","I-OS","E-OS","S-OS",
                "B-PROT","I-PROT","E-PROT","S-PROT",
                "B-SECTEAM","I-SECTEAM","E-SECTEAM","S-SECTEAM",
                "B-SHA2","E-SHA2","S-SHA2",
                "B-TIME","I-TIME","E-TIME","S-TIME",
                "B-TOOL","I-TOOL","E-TOOL","S-TOOL",
                "B-URL","I-URL","E-URL","S-URL",
                "B-VULID","S-VULID",
                "B-VULNAME","I-VULNAME","E-VULNAME","S-VULNAME",
                "O","PROT","S-SHA1","S-MD5","E-S-SECTEAM","S-S-SECTEAM"
            ]
        )
    },
    required=["token","label"]
)


schema = types.Schema(type="array", items=token_schema)

# Initialize client
client = genai.Client()

sentence = "APT29 used Cobalt Strike on 192.168.0.1 and dropped malware.exe"

response = client.models.generate_content(
    model="gemini-2.5-flash",
    contents=f"Label each token in this sentence using BIO/S/E scheme with ONLY the allowed labels: {sentence}",
    config={
        "response_mime_type": "application/json",
        "response_schema": schema
    }
)

# Convert to .txt format
import json
labeled_tokens = json.loads(response.text)
with open("ner_dataset.txt", "w") as f:
    for token_obj in labeled_tokens:
        f.write(f"{token_obj['token']} {token_obj['label']}\n")
    f.write("\n")
