# S3 Automation Tool

A production-ready Python CLI to **upload, list, download, delete, sync, and presign** files with Amazon S3 — with **proper logging** and **error handling**.

> Perfect for a portfolio/resume project: clean architecture, robust CLI, and ready for demos.

---

## ✨ Features
- Upload single files with optional `--public` ACL and automatic `ContentType` detection.
- List bucket contents with pagination.
- Download and delete objects.
- One‑way **sync** of a local directory to S3 (`--delete` to remove remote orphans).
- Generate **presigned URLs** for easy sharing.
- Uses **boto3 default credential chain** (env vars, shared config, instance profile, etc.).
- **Rotating file logs** (`s3_automation.log`) + console logs.
- Works with `--profile` and `--region` overrides.

---

## 🧱 Project Structure
```
s3-automation-tool/
├─ s3_automation.py       # CLI tool
├─ requirements.txt
└─ README.md
```

---

## 🚀 Quick Start

1) **Create/activate a virtualenv (recommended):**
```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
```

2) **Install deps:**
```bash
pip install -r requirements.txt
```

3) **Configure AWS credentials** (choose one):
- Environment variables `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`
- Or set up AWS CLI and profiles:
  ```bash
  aws configure            # default profile
  aws configure --profile myprofile
  ```

4) **Run commands:**
```bash
# Upload a file
python s3_automation.py upload --bucket YOUR_BUCKET --file ./path/to/file.jpg --prefix uploads/

# List files
python s3_automation.py list --bucket YOUR_BUCKET --prefix uploads/

# Download
python s3_automation.py download --bucket YOUR_BUCKET --key uploads/file.jpg --dest ./downloads/

# Delete
python s3_automation.py delete --bucket YOUR_BUCKET --key uploads/file.jpg

# Sync a folder (local -> S3)
python s3_automation.py sync --bucket YOUR_BUCKET --dir ./my_folder --prefix backups/ --delete

# Presign a URL (1 hour)
python s3_automation.py presign --bucket YOUR_BUCKET --key uploads/file.jpg --expires 3600
```

> Add `-v` or `-vv` for more logs, and `--profile` / `--region` if needed (e.g., `--region ap-south-1`).

---

## 📝 Logging
- Console shows concise logs; file logs are written to `s3_automation.log` with rotation (max ~1MB × 3).
- Errors include stack traces in the log file for easier debugging.

---

## ⏱️ Automation (Cron & Task Scheduler)

**Linux/macOS (cron):**
```bash
# Every night at 1:30 AM, sync a folder to S3
30 1 * * * /usr/bin/python /path/to/s3_automation.py sync --bucket YOUR_BUCKET --dir /data --prefix nightly/ >> /var/log/s3_sync.log 2>&1
```

**Windows (Task Scheduler):**
- Create a Basic Task → Action: Start a Program  
  Program/script: `python`  
  Add arguments: `C:\path\to\s3_automation.py sync --bucket YOUR_BUCKET --dir C:\data --prefix nightly\`

---

## 🔐 Security Notes
- **Never** hardcode secrets in the script or commit credentials.
- Prefer IAM roles (on EC2/Lambda) or AWS profiles in `~/.aws/credentials` for local dev.
- For public objects, use the `--public` flag intentionally.

---

## 📦 Packaging (optional)
Make it executable:
```bash
chmod +x s3_automation.py
./s3_automation.py list --bucket YOUR_BUCKET
```

Or install as a CLI with `pipx`/entry points later if you want to evolve it.

---

## 📚 Resume-Ready Summary
> Built a Python CLI to upload, list, download, delete, and sync files on AWS S3 with rotating logs, robust error handling, presigned links, and support for scheduled automation (cron/Task Scheduler). Utilizes boto3’s default credential chain with optional profile/region overrides.
