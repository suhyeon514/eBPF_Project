import hashlib
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse

router = APIRouter(prefix="/api/v1/artifacts", tags=["아티팩트(Artifacts)"])

ALLOWED_COMPONENTS = {"tetragon", "fluent-bit"}

BASE_DIR = Path(__file__).resolve().parents[4]
artifacts_dir_env = os.getenv("ARTIFACTS_DIR", "artifacts")

if not Path(artifacts_dir_env).is_absolute():
    ARTIFACTS_DIR = BASE_DIR / artifacts_dir_env
else:
    ARTIFACTS_DIR = Path(artifacts_dir_env)


def _find_artifact(component: str) -> Path | None:
    """컴포넌트 디렉터리에서 첫 번째 파일을 반환합니다."""
    comp_dir = ARTIFACTS_DIR / component
    if not comp_dir.is_dir():
        return None
    files = [f for f in comp_dir.iterdir() if f.is_file()]
    return files[0] if files else None


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


@router.get("/manifest")
def get_artifact_manifest(component: str = Query(..., description="tetragon 또는 fluent-bit")):
    """
    컴포넌트 아티팩트의 메타데이터(파일명, SHA256)를 반환합니다.
    download_url이 빈 문자열이면 클라이언트가 /api/v1/artifacts/download 를 사용합니다.
    """
    if component not in ALLOWED_COMPONENTS:
        raise HTTPException(status_code=400, detail=f"component는 {ALLOWED_COMPONENTS} 중 하나여야 합니다.")

    artifact = _find_artifact(component)
    if artifact is None:
        raise HTTPException(status_code=404, detail=f"{component} 아티팩트 파일을 찾을 수 없습니다.")

    return {
        "component": component,
        "file_name": artifact.name,
        "sha256": _sha256(artifact),
        "download_url": "",
    }


@router.get("/download")
def download_artifact(component: str = Query(..., description="tetragon 또는 fluent-bit")):
    """컴포넌트 아티팩트 바이너리를 스트리밍 다운로드합니다."""
    if component not in ALLOWED_COMPONENTS:
        raise HTTPException(status_code=400, detail=f"component는 {ALLOWED_COMPONENTS} 중 하나여야 합니다.")

    artifact = _find_artifact(component)
    if artifact is None:
        raise HTTPException(status_code=404, detail=f"{component} 아티팩트 파일을 찾을 수 없습니다.")

    return FileResponse(
        path=str(artifact),
        filename=artifact.name,
        media_type="application/octet-stream",
    )
