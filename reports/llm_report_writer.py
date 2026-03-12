from pathlib import Path
from utils.timezone import local_tag


def write_llm_summary(summary_text: str, out_dir: str = "reports") -> str:
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    ts = local_tag()
    file_path = out_path / f"llm_summary_{ts}.md"

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(summary_text)

    return str(file_path)
