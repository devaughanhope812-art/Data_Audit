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
import pathlib
import platform
import uuid
import win32security  
import ntsecuritycon  
import win32file
import win32con
import ntplib 
from docx import Document
from datetime import datetime, timezone

# SILENCE EXCEL WARNINGS
warnings.filterwarnings("ignore", category=UserWarning, module="openpyxl")

# 1. CONFIGURATION
MAX_PEEK_SIZE = 1024 * 5 
MAX_FILE_SIZE = 1024 * 1024 * 2   
MAX_PDF_SIZE = 1024 * 1024 * 5    
WORKERS = 8                      
QUEUE_LIMIT = 100                
TIMEOUT_PER_FILE = 5            
REPORT_INTERVAL = 300            
TIMESTAMP = datetime.now().strftime('%Y%m%d_%H%M%S')

def get_network_time():
    try:
        client = ntplib.NTPClient()
        response = client.request('pool.ntp.org', version=3)
        return datetime.fromtimestamp(response.tx_time, timezone.utc).isoformat()
    except:
        return datetime.now(timezone.utc).isoformat()

ENV_INFO = {
    "Hostname": socket.gethostname(),
    "OS": platform.platform(),
    "MAC": ':'.join(re.findall('..', '%012x' % uuid.getnode())),
    "Audit_User": os.getlogin() if hasattr(os, 'getlogin') else "N/A",
    "Network_Verified_Time": get_network_time(),
    "Python_Version": platform.python_version()
}

# REMOVED .pdf FROM VALID_EXTENSIONS
VALID_EXTENSIONS = {'.txt', '.docx', '.xlsx', '.xlsm', '.csv', '.json', '.log', '.rtf'}
SKIP_FOLDERS = {'$RECYCLE.BIN', 'System Volume Information', 'Windows', 'Program Files', 'Temp'}

USER_REGISTRY = []
NAME_REGEX_STRING = "|".join(re.escape(name) for name in USER_REGISTRY) if USER_REGISTRY else "[]"

SENSITIVE_PATTERNS = {
    "Names": [re.compile(NAME_REGEX_STRING, re.IGNORECASE)] if USER_REGISTRY else [],
    "Salary": [re.compile(r"salary|wage|bonus|paycheck|income", re.IGNORECASE)],
    "Credentials": [re.compile(r"password|username|login", re.IGNORECASE)],
    "Identity": [re.compile(r"ssn|social\s*security|passport|identification\s*number|driver'?s\s*license", re.IGNORECASE)],
    "Financial": [re.compile(r"tax\s*return|account\s*number|routing\s*number|direct\s*deposit", re.IGNORECASE)]
}

def get_file_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except: return "HASH_ERROR"

def get_forensic_metadata(file_path):
    metadata = {
        "Owner": "UNKNOWN", 
        "Permissions": "N/A", 
        "Mode": "N/A",
        "Is_Encrypted_At_Rest": "No"
    }
    try:
        st = os.stat(file_path)
        metadata["Mode"] = oct(st.st_mode & 0o777)
        
        attrs = win32file.GetFileAttributes(file_path)
        if attrs & win32con.FILE_ATTRIBUTE_ENCRYPTED:
            metadata["Is_Encrypted_At_Rest"] = "Yes (NTFS)"
            
        sd = win32security.GetFileSecurity(file_path, 
            win32security.OWNER_SECURITY_INFORMATION | 
            win32security.DACL_SECURITY_INFORMATION)
            
        owner_sid = sd.GetSecurityDescriptorOwner()
        name, domain, _ = win32security.LookupAccountSid(None, owner_sid)
        metadata["Owner"] = f"{domain}\\{name}"
        
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl:
            perms = []
            for i in range(dacl.GetAceCount()):
                rev, access, sid = dacl.GetAce(i)
                u_name, u_dom, _ = win32security.LookupAccountSid(None, sid)
                type_str = "Allow" if dacl.GetAce(i)[0][0] == win32con.ACCESS_ALLOWED_ACE_TYPE else "Deny"
                perms.append(f"{u_dom}\\{u_name}:{type_str}")
            metadata["Permissions"] = " | ".join(perms)
            
    except: pass
    return metadata

def extract_content_sample(file_path, ext):
    try:
        if ext == '.pdf':
            with pdfplumber.open(file_path) as pdf:
                return pdf.pages[0].extract_text() if pdf.pages else ""
        elif ext in ['.xlsx', '.xlsm']:
            return pd.read_excel(file_path, nrows=10, engine='openpyxl').to_string()
        elif ext == '.docx':
            doc = Document(file_path)
            return "\n".join([p.text for p in doc.paragraphs[:10]])
        else:
            with open(file_path, 'r', errors='ignore') as f:
                return f.read(MAX_PEEK_SIZE)
    except: return ""

def scan_file(file_path, force_filename_only=False):
    try:
        file_name = os.path.basename(file_path)
        ext = os.path.splitext(file_path)[1].lower()
        found_hits = {}
        hit_details = []
        total_extracted_hits = 0 
        bytes_scanned = 0

        # Check if filename triggers a content scan
        name_trigger = any(any(p.search(file_name) for p in patterns) for patterns in SENSITIVE_PATTERNS.values())
        
        # Logic: Extract content if it's a valid extension OR if it's a PDF with a name match
        should_extract = (not force_filename_only and ext in VALID_EXTENSIONS) or (ext == '.pdf' and name_trigger)

        text_to_scan = file_name
        extracted_content = ""
        
        if should_extract:
            f_size = os.path.getsize(file_path)
            size_limit = MAX_PDF_SIZE if ext == '.pdf' else MAX_FILE_SIZE
            if f_size <= size_limit:
                extracted_content = extract_content_sample(file_path, ext)
                bytes_scanned = len(extracted_content.encode(errors='ignore'))
                text_to_scan += " " + extracted_content

        # Scan Logic
        for category, patterns in SENSITIVE_PATTERNS.items():
            for pattern in patterns:
                if extracted_content:
                    extracted_matches = pattern.findall(extracted_content)
                    total_extracted_hits += len(extracted_matches)
                
                matches = pattern.findall(text_to_scan)
                if matches:
                    found_hits[category] = matches[0]
                    m = pattern.search(text_to_scan)
                    start, end = m.span()
                    raw_snippet = text_to_scan[max(0, start-50):min(len(text_to_scan), end+50)]
                    hashed_snippet = hashlib.sha256(raw_snippet.encode()).hexdigest()
                    hit_details.append({"cat": category, "hash": hashed_snippet})

        final_reasons = []
        if "Salary" in found_hits and "Names" in found_hits:
            final_reasons.append(f"Salary + Name ({found_hits['Salary']} | {found_hits['Names']})")
        for cat in ["Credentials", "Identity", "Financial", "Biometric"]:
            if cat in found_hits: final_reasons.append(f"{cat} ({found_hits[cat]})")

        if final_reasons:
            meta = get_forensic_metadata(file_path)
            stats = os.stat(file_path)
            sample_kb = bytes_scanned / 1024
            density = round(total_extracted_hits / sample_kb, 2) if sample_kb > 0 else 0

            return {
                "File Name": file_name,
                "Patterns Found": " | ".join(final_reasons),
                "Hit_Density_per_KB": density,
                "Bytes_Scanned_Content": bytes_scanned,
                "Owner": meta["Owner"],
                "Is_Encrypted": meta["Is_Encrypted_At_Rest"],
                "User Permissions (ACL)": meta["Permissions"],
                "Mode": meta["Mode"],
                "Date Created": datetime.fromtimestamp(stats.st_ctime, timezone.utc).isoformat(),
                "Date Modified": datetime.fromtimestamp(stats.st_mtime, timezone.utc).isoformat(),
                "Date Accessed": datetime.fromtimestamp(stats.st_atime, timezone.utc).isoformat(),
                "Snippet_SHA256": [h['hash'] for h in hit_details],
                "Full Path": file_path,
                "File Hash": get_file_hash(file_path),
                "Discovery Time": datetime.now(timezone.utc).isoformat()
            }
    except: pass
    return None

def run_audit(scan_paths, dest_dir):
    if not os.path.exists(dest_dir): os.makedirs(dest_dir, exist_ok=True)
    
    log_file_path = os.path.join(dest_dir, f"forensic_audit_{TIMESTAMP}.json")
    excel_report_path = os.path.join(dest_dir, f"audit_summary_{TIMESTAMP}.xlsx")
    script_snapshot_path = os.path.join(dest_dir, f"methodology_snapshot_{TIMESTAMP}.py")
    receipt_path = os.path.join(dest_dir, "audit_receipt_HASH.txt")
    
    findings = []
    processed_count = 0
    last_report_time = time.time()
    all_hashes = []
    
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
                    
                    # Pattern check on filename
                    hit_trigger = any(any(p.search(f) for p in patterns) for patterns in SENSITIVE_PATTERNS.values())
                    
                    # LOGIC: 
                    # 1. Process if extension is in VALID_EXTENSIONS
                    # 2. Process if it's a .pdf AND the name matches a pattern
                    # 3. If extension not in VALID and no name match, skip entirely.
                    
                    if ext in VALID_EXTENSIONS or (ext == '.pdf' and hit_trigger):
                        # Force name only if it's not a "valid" content extension (like a weird file with a name hit)
                        only_name = (ext not in VALID_EXTENSIONS and ext != '.pdf')
                        futures.append(executor.submit(scan_file, file_path, only_name))
                    
                    processed_count += 1
                    if len(futures) >= QUEUE_LIMIT:
                        done, pending = concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_COMPLETED)
                        futures = list(pending)
                        for fut in done:
                            res = fut.result()
                            if res: 
                                findings.append(res)
                                all_hashes.append(res["File Hash"])
                        if time.time() - last_report_time >= REPORT_INTERVAL:
                            print(f"[STATUS] {datetime.now().strftime('%H:%M:%S')} | Seen: {processed_count} | Hits: {len(findings)}")
                            last_report_time = time.time()

        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res: 
                findings.append(res)
                all_hashes.append(res["File Hash"])

    # Audit Summary
    evidence = {"Env": ENV_INFO, "metadata": {"total_processed": processed_count}, "findings": findings}
    with open(log_file_path, "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=4)
    
    shutil.copy2(__file__, script_snapshot_path)
    
    if findings:
        pd.DataFrame(findings).to_excel(excel_report_path, index=False)
    
    root_hash_obj = hashlib.sha256("".join(sorted(all_hashes)).encode())
    merkle_root = root_hash_obj.hexdigest() if all_hashes else "EMPTY_SET"

    with open(receipt_path, "w") as receipt:
        receipt.write("=== FORENSIC DIGITAL RECEIPT ===\n")
        receipt.write(f"Audit Verified Time: {ENV_INFO['Network_Verified_Time']}\n")
        receipt.write(f"Merkle Root of Scan: {merkle_root}\n\n")
        
        target_files = [
            ("JSON EVIDENCE", log_file_path),
            ("EXCEL REPORT", excel_report_path),
            ("METHODOLOGY SNAPSHOT", script_snapshot_path)
        ]
        
        for label, path in target_files:
            if os.path.exists(path):
                file_hash = get_file_hash(path)
                receipt.write(f"FILE: {os.path.basename(path)}\nTYPE: {label}\nSHA-256: {file_hash}\n" + "-"*45 + "\n")
                
    print(f"\nAUDIT COMPLETE. Results and Receipt saved to: {dest_dir}")

if __name__ == "__main__":
    scan_input = input("Paths to SCAN (comma separated): ")
    scan_list = scan_input.split(',')
    save_path = input("Path to SAVE Evidence: ").strip().strip('"')
    run_audit(scan_list, save_path)
