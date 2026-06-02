import os
import re
import pandas as pd
import hashlib
import json
import socket
import pdfplumber
import warnings
import stat
import shutil
import concurrent.futures
import time
from docx import Document
from datetime import datetime, timezone

# --- SILENCE EXCEL WARNINGS ---
warnings.filterwarnings("ignore", category=UserWarning, module="openpyxl")

# --- 1. CONFIGURATION ---
MAX_PEEK_SIZE = 1024 * 5 
MAX_FILE_SIZE = 1024 * 1024 * 2   # 2MB Limit for Content Scanning
MAX_PDF_SIZE = 1024 * 500         # 500KB Limit for PDF Content (Speed Guard)
WORKERS = 4                      # Stable for Network Drives (P:)
QUEUE_LIMIT = 100                
TIMEOUT_PER_FILE = 5             
REPORT_INTERVAL = 300            # Status report every 300 seconds (5 minutes)
TIMESTAMP = datetime.now().strftime('%Y%m%d_%H%M%S')

# Configuration for Output
SCRIPT_LOCATION = os.path.dirname(os.path.abspath(__file__))
EXCEL_REPORT = os.path.join(SCRIPT_LOCATION, f"audit_summary_{TIMESTAMP}.xlsx")

# These extensions get "Deep Content" scanning
VALID_EXTENSIONS = {'.txt', '.docx', '.xlsx', '.xlsm', '.csv', '.json', '.log', '.rtf'}

# System folders to ignore entirely for speed
SKIP_FOLDERS = {'$RECYCLE.BIN', 'System Volume Information', 'Windows', 'Program Files', 'Temp'}

# ORIGINAL DICTIONARY RESTORED
SENSITIVE_PATTERNS = {
    "Credentials": [re.compile(r"password|username|login", re.IGNORECASE)],
    "Identity": [re.compile(r"ssn|social\s*security|passport|identification\s*number", re.IGNORECASE)],
    "Financial": [re.compile(r"tax\s*return|account\s*number|routing\s*number|direct\s*deposit", re.IGNORECASE)]
}

def get_file_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except:
        return "HASH_ERROR"

def extract_content_sample(file_path, ext):
    try:
        if ext == '.pdf':
            with pdfplumber.open(file_path) as pdf:
                if pdf.pages:
                    return pdf.pages[0].extract_text() or ""
                return ""
        elif ext in ['.xlsx', '.xlsm']:
            return pd.read_excel(file_path, nrows=10, engine='openpyxl').to_string()
        elif ext == '.docx':
            doc = Document(file_path)
            return "\n".join([p.text for p in doc.paragraphs[:10]])
        else:
            with open(file_path, 'r', errors='ignore') as f:
                return f.read(MAX_PEEK_SIZE)
    except:
        return ""

def scan_file(file_path, force_filename_only=False):
    """Performs forensic analysis and captures the specific string matched."""
    try:
        file_name = os.path.basename(file_path)
        ext = os.path.splitext(file_path)[1].lower()
        matches_found = []

        # Check Filename
        for category, patterns in SENSITIVE_PATTERNS.items():
            for pattern in patterns:
                m = pattern.search(file_name)
                if m:
                    matches_found.append(f"{category} (Filename Match: {m.group()})")

        # Check Content
        if not force_filename_only and ext in VALID_EXTENSIONS:
            f_size = os.path.getsize(file_path)
            size_limit = MAX_PDF_SIZE if ext == '.pdf' else MAX_FILE_SIZE
            
            if f_size <= size_limit:
                sample = extract_content_sample(file_path, ext)
                for category, patterns in SENSITIVE_PATTERNS.items():
                    for pattern in patterns:
                        m = pattern.search(sample)
                        if m:
                            matches_found.append(f"{category} (Content Match: {m.group()})")

        if matches_found:
            return {
                "File Name": file_name,
                "Patterns Found": " | ".join(list(set(matches_found))),
                "Full Path": file_path,
                "File Hash": get_file_hash(file_path),
                "Discovery Time": datetime.now(timezone.utc).isoformat()
            }
    except:
        pass
    return None

def run_audit(scan_paths, dest_dir):
    if not os.path.exists(dest_dir): os.makedirs(dest_dir, exist_ok=True)
    
    log_file_path = os.path.join(dest_dir, f"forensic_audit_{TIMESTAMP}.json")
    script_snapshot_path = os.path.join(dest_dir, f"methodology_snapshot_{TIMESTAMP}.py")
    receipt_path = os.path.join(dest_dir, "audit_receipt_HASH.txt")
    
    findings = []
    processed_count = 0
    last_report_time = time.time()

    print(f"[*] AUDIT ACTIVE: Scanning input paths...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futures = []
        for path in scan_paths:
            path = path.strip().strip('"')
            if not os.path.exists(path): continue
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if d not in SKIP_FOLDERS]
                for f in files:
                    file_path = os.path.join(root, f)
                    ext = os.path.splitext(f)[1].lower()
                    
                    hit_trigger = False
                    for patterns in SENSITIVE_PATTERNS.values():
                        if any(p.search(f) for p in patterns):
                            hit_trigger = True
                            break

                    if hit_trigger or ext in VALID_EXTENSIONS:
                        try:
                            with open(file_path, 'rb') as _: pass
                        except:
                            processed_count += 1
                            continue
                        only_name = (ext not in VALID_EXTENSIONS)
                        futures.append(executor.submit(scan_file, file_path, only_name))
                    
                    processed_count += 1

                    if len(futures) >= QUEUE_LIMIT:
                        done, pending = concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_COMPLETED)
                        futures = list(pending)
                        for fut in done:
                            try:
                                res = fut.result(timeout=TIMEOUT_PER_FILE)
                                if res: findings.append(res)
                            except: pass
                        
                        if time.time() - last_report_time >= REPORT_INTERVAL:
                            print(f"[STATUS] {datetime.now().strftime('%H:%M:%S')} | Seen: {processed_count} | Hits: {len(findings)}")
                            last_report_time = time.time()

        for fut in concurrent.futures.as_completed(futures):
            try:
                res = fut.result(timeout=TIMEOUT_PER_FILE)
                if res: findings.append(res)
            except: pass

    # SAVE RESULTS
    evidence = {"metadata": {"total_processed": processed_count}, "findings": findings}
    with open(log_file_path, "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=4)
    
    shutil.copy2(__file__, script_snapshot_path)
    
    if findings:
        pd.DataFrame(findings).to_excel(EXCEL_REPORT, index=False)

    # DIGITAL RECEIPT (HASH OF JSON AND METHODOLOGY)
    with open(receipt_path, "w") as receipt:
        receipt.write("=== FORENSIC DIGITAL RECEIPT ===\n")
        receipt.write(f"Timestamp: {datetime.now()}\n\n")
        for label, path in [("JSON EVIDENCE", log_file_path), ("METHODOLOGY SNAPSHOT", script_snapshot_path)]:
            file_hash = get_file_hash(path)
            receipt.write(f"FILE: {os.path.basename(path)}\n")
            receipt.write(f"TYPE: {label}\n")
            receipt.write(f"SHA-256: {file_hash}\n")
            receipt.write("-" * 45 + "\n")

    print(f"\nAUDIT COMPLETE. Receipt saved to: {receipt_path}")

if __name__ == "__main__":
    scan_input = input("Paths to SCAN (comma separated): ")
    scan_list = scan_input.split(',')
    save_path = input("Path to SAVE Evidence: ").strip().strip('"')
    run_audit(scan_list, save_path)
