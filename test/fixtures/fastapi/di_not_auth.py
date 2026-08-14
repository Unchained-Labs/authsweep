# Regression fixture. FastAPI's Depends() is general dependency injection, not
# proof of an auth check. An earlier version of authsweep treated ANY Depends()
# as a guard and reported a false clean on a real service whose paid endpoints
# were wide open. Shape taken from Unchained-Labs/lavoix.
from fastapi import Depends, FastAPI, File, UploadFile

from .auth import current_user
from .service import AudioService


def create_app() -> FastAPI:
    app = FastAPI()

    def get_service() -> AudioService:
        return app.state.audio_service

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    # NOT guarded — Depends(get_service) is a service locator, not an auth check.
    @app.post("/v1/stt/transcribe")
    async def transcribe(
        file: UploadFile = File(...),
        audio_service: AudioService = Depends(get_service),
    ):
        return await audio_service.transcribe(await file.read())

    # Genuinely guarded — the dependency is named like an auth check.
    @app.post("/v1/tts/synthesize")
    async def synthesize(
        payload: dict,
        user = Depends(current_user),
        audio_service: AudioService = Depends(get_service),
    ):
        return await audio_service.synthesize(payload["text"])

    return app
