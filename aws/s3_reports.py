from __future__ import annotations

from pathlib import Path


def upload_text_report(
    s3_client,
    bucket: str,
    key: str,
    text: str,
    content_type: str,
) -> str:
    s3_client.put_object(
        Bucket=bucket,
        Key=key,
        Body=text.encode("utf-8"),
        ContentType=content_type,
    )
    return f"s3://{bucket}/{key}"


def upload_file_report(
    s3_client,
    bucket: str,
    key: str,
    file_path: Path,
    content_type: str,
) -> str:
    with file_path.open("rb") as handle:
        s3_client.put_object(
            Bucket=bucket,
            Key=key,
            Body=handle,
            ContentType=content_type,
        )
    return f"s3://{bucket}/{key}"
