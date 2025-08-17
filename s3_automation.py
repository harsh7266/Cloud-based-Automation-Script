#!/usr/bin/env python3
"""
S3 Automation Tool
------------------
A robust Python CLI to upload, download, list, delete, sync, and presign files on AWS S3.
- Uses boto3 default credential chain (env vars, shared config, instance profile, etc.)
- Optional --profile and --region overrides
- Structured logging to file and console
- Safe error handling with clear exit codes
"""

import argparse
import logging
from logging.handlers import RotatingFileHandler
import os
import sys
import time
import mimetypes
from pathlib import Path
from typing import Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError

APP_NAME = "s3_automation"
LOG_FILE = f"{APP_NAME}.log"


def setup_logging(verbosity: int) -> None:
    """Configure console + rotating file logging."""
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG

    logger = logging.getLogger()
    logger.setLevel(level)

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    ch.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))

    # Rotating file handler
    fh = RotatingFileHandler(LOG_FILE, maxBytes=1_000_000, backupCount=3)
    fh.setLevel(logging.DEBUG)  # always capture full detail to file
    fh.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(funcName)s:%(lineno)d | %(message)s"
    ))

    logger.handlers.clear()
    logger.addHandler(ch)
    logger.addHandler(fh)


def make_session(profile: Optional[str], region: Optional[str]) -> boto3.session.Session:
    """Create a boto3 Session using default chain, with optional overrides."""
    kwargs = {}
    if profile:
        kwargs["profile_name"] = profile
    session = boto3.Session(**kwargs)
    if region:
        # Prefer explicit region if provided
        return boto3.Session(profile_name=profile, region_name=region) if profile else boto3.Session(region_name=region)
    return session


def get_s3_client(session: boto3.session.Session):
    return session.client("s3")


def guess_content_type(path: str) -> Optional[str]:
    ctype, _ = mimetypes.guess_type(path)
    return ctype


def cmd_upload(args) -> int:
    s3 = get_s3_client(make_session(args.profile, args.region))
    src = Path(args.file).expanduser().resolve()
    if not src.is_file():
        logging.error("Source file not found: %s", src)
        return 2

    key = args.key or (args.prefix.rstrip("/") + "/" if args.prefix else "") + src.name
    extra = {}
    if args.public:
        extra["ACL"] = "public-read"
    ctype = guess_content_type(str(src))
    if ctype:
        extra["ContentType"] = ctype

    try:
        s3.upload_file(str(src), args.bucket, key, ExtraArgs=extra or None)
        url_hint = f"s3://{args.bucket}/{key}"
        logging.info("Uploaded %s -> %s", src, url_hint)
        print(f"✅ Uploaded: {src} -> {url_hint}")
        return 0
    except (ClientError, EndpointConnectionError, NoCredentialsError) as e:
        logging.exception("Upload failed")
        print(f"❌ Upload failed: {e}")
        return 1


def cmd_download(args) -> int:
    s3 = get_s3_client(make_session(args.profile, args.region))
    dest = Path(args.dest).expanduser()
    if dest.is_dir():
        dest = dest / Path(args.key).name
    dest.parent.mkdir(parents=True, exist_ok=True)

    try:
        s3.download_file(args.bucket, args.key, str(dest))
        print(f"✅ Downloaded: s3://{args.bucket}/{args.key} -> {dest}")
        logging.info("Downloaded s3://%s/%s -> %s", args.bucket, args.key, dest)
        return 0
    except (ClientError, EndpointConnectionError, NoCredentialsError) as e:
        logging.exception("Download failed")
        print(f"❌ Download failed: {e}")
        return 1


def cmd_delete(args) -> int:
    s3 = get_s3_client(make_session(args.profile, args.region))
    try:
        s3.delete_object(Bucket=args.bucket, Key=args.key)
        print(f"🗑️  Deleted: s3://{args.bucket}/{args.key}")
        logging.info("Deleted s3://%s/%s", args.bucket, args.key)
        return 0
    except (ClientError, EndpointConnectionError, NoCredentialsError) as e:
        logging.exception("Delete failed")
        print(f"❌ Delete failed: {e}")
        return 1


def cmd_list(args) -> int:
    s3 = get_s3_client(make_session(args.profile, args.region))
    token = None
    printed = 0
    try:
        while True:
            kwargs = {"Bucket": args.bucket, "MaxKeys": 1000}
            if args.prefix:
                kwargs["Prefix"] = args.prefix
            if token:
                kwargs["ContinuationToken"] = token
            resp = s3.list_objects_v2(**kwargs)
            for obj in resp.get("Contents", []):
                size = obj.get("Size", 0)
                lastmod = obj.get("LastModified", "")
                print(f"{obj['Key']}\t{size}\t{lastmod}")
                printed += 1
            if resp.get("IsTruncated"):
                token = resp.get("NextContinuationToken")
            else:
                break
        if printed == 0:
            print("(no objects)")
        logging.info("Listed %d objects from s3://%s/%s", printed, args.bucket, args.prefix or "")
        return 0
    except (ClientError, EndpointConnectionError, NoCredentialsError) as e:
        logging.exception("List failed")
        print(f"❌ List failed: {e}")
        return 1


def eprint(*a, **k):
    print(*a, file=sys.stderr, **k)


def walk_local_files(root: Path):
    for p in root.rglob("*"):
        if p.is_file():
            yield p


def cmd_sync(args) -> int:
    """
    One-way sync local -> S3.
    - Uploads new/changed files (by size + mtime compare).
    - Optionally deletes remote objects not present locally (--delete).
    """
    session = make_session(args.profile, args.region)
    s3 = get_s3_client(session)

    local_root = Path(args.dir).expanduser().resolve()
    if not local_root.is_dir():
        logging.error("Local directory not found: %s", local_root)
        print(f"❌ Local directory not found: {local_root}")
        return 2

    # Build remote object set for deletes, and for comparison
    remote_keys = set()
    paginator = session.client("s3").get_paginator("list_objects_v2")
    prefix = (args.prefix or "").rstrip("/")
    try:
        for page in paginator.paginate(Bucket=args.bucket, Prefix=prefix + ("/" if prefix else "")):
            for obj in page.get("Contents", []):
                remote_keys.add(obj["Key"])
    except (ClientError, EndpointConnectionError, NoCredentialsError) as e:
        logging.exception("Failed to list remote objects for sync")
        print(f"❌ Failed to list remote objects: {e}")
        return 1

    uploaded = 0
    skipped = 0
    for f in walk_local_files(local_root):
        rel = f.relative_to(local_root).as_posix()
        key = f"{prefix}/{rel}" if prefix else rel

        # Heuristic: upload if not present or size differs
        try:
            head = s3.head_object(Bucket=args.bucket, Key=key)
            remote_size = head.get("ContentLength", -1)
            if remote_size == f.stat().st_size:
                skipped += 1
                continue
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code not in ("404", "NoSuchKey"):
                logging.exception("head_object failed for %s", key)

        extra = {}
        ctype = guess_content_type(str(f))
        if ctype:
            extra["ContentType"] = ctype

        try:
            s3.upload_file(str(f), args.bucket, key, ExtraArgs=extra or None)
            uploaded += 1
            logging.info("Synced file %s -> s3://%s/%s", f, args.bucket, key)
            print(f"⬆️  {f} -> s3://{args.bucket}/{key}")
        except (ClientError, EndpointConnectionError, NoCredentialsError) as e:
            logging.exception("Upload during sync failed for %s", f)
            print(f"❌ Upload failed for {f}: {e}")
            return 1

    deleted = 0
    if args.delete:
        # delete keys that start with prefix and are not in local set
        local_keys = set()
        for f in walk_local_files(local_root):
            rel = f.relative_to(local_root).as_posix()
            key = f"{prefix}/{rel}" if prefix else rel
            local_keys.add(key)

        to_delete = [k for k in remote_keys if k.startswith(prefix) and k not in local_keys]
        # Batch delete in chunks of 1000
        for i in range(0, len(to_delete), 1000):
            chunk = to_delete[i:i+1000]
            try:
                resp = s3.delete_objects(
                    Bucket=args.bucket,
                    Delete={"Objects": [{"Key": k} for k in chunk], "Quiet": True},
                )
                deleted += len(resp.get("Deleted", []))
            except (ClientError, EndpointConnectionError, NoCredentialsError) as e:
                logging.exception("Batch delete failed during sync")
                print(f"❌ Batch delete failed: {e}")
                return 1

    print(f"✅ Sync complete. Uploaded: {uploaded}, Skipped: {skipped}, Deleted: {deleted}")
    return 0


def cmd_presign(args) -> int:
    s3 = get_s3_client(make_session(args.profile, args.region))
    try:
        url = s3.generate_presigned_url(
            ClientMethod="get_object",
            Params={"Bucket": args.bucket, "Key": args.key},
            ExpiresIn=args.expires,
        )
        print(url)
        logging.info("Generated presigned URL for s3://%s/%s (expires=%ss)", args.bucket, args.key, args.expires)
        return 0
    except (ClientError, EndpointConnectionError, NoCredentialsError) as e:
        logging.exception("Presign failed")
        print(f"❌ Presign failed: {e}")
        return 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="S3 Automation Tool — upload, download, list, delete, sync, presign."
    )
    p.add_argument("--profile", help="AWS profile name (from ~/.aws/credentials)")
    p.add_argument("--region", help="AWS region override, e.g., ap-south-1")
    p.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity (-v, -vv)")

    sub = p.add_subparsers(dest="command", required=True)

    # upload
    up = sub.add_parser("upload", help="Upload a single file to S3")
    up.add_argument("--bucket", required=True, help="Target S3 bucket")
    up.add_argument("--file", required=True, help="Local file path")
    up.add_argument("--key", help="S3 object key (defaults to filename)")
    up.add_argument("--prefix", help="Prefix to prepend to object key")
    up.add_argument("--public", action="store_true", help="Make object public-read")
    up.set_defaults(func=cmd_upload)

    # download
    down = sub.add_parser("download", help="Download a single file from S3")
    down.add_argument("--bucket", required=True)
    down.add_argument("--key", required=True)
    down.add_argument("--dest", required=True, help="Destination file or directory")
    down.set_defaults(func=cmd_download)

    # delete
    dele = sub.add_parser("delete", help="Delete a single object from S3")
    dele.add_argument("--bucket", required=True)
    dele.add_argument("--key", required=True)
    dele.set_defaults(func=cmd_delete)

    # list
    ls = sub.add_parser("list", help="List objects in a bucket/prefix")
    ls.add_argument("--bucket", required=True)
    ls.add_argument("--prefix", help="Prefix filter", default=None)
    ls.set_defaults(func=cmd_list)

    # sync
    sync = sub.add_parser("sync", help="One-way sync a local directory to S3")
    sync.add_argument("--bucket", required=True)
    sync.add_argument("--dir", required=True, help="Local directory to sync")
    sync.add_argument("--prefix", help="Remote prefix (folder) in bucket")
    sync.add_argument("--delete", action="store_true", help="Delete remote files not present locally")
    sync.set_defaults(func=cmd_sync)

    # presign
    ps = sub.add_parser("presign", help="Generate a presigned GET URL for an object")
    ps.add_argument("--bucket", required=True)
    ps.add_argument("--key", required=True)
    ps.add_argument("--expires", type=int, default=3600, help="Expiry in seconds (default: 3600)")
    ps.set_defaults(func=cmd_presign)

    return p


def main(argv=None) -> int:
    argv = argv or sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(args.verbose)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("Interrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
