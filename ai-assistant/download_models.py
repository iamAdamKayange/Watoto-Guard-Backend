"""Fetch the bounded open speech models during image build, not on a user's first voice turn."""

import gc
import os

from faster_whisper import WhisperModel

import main


def main_download() -> None:
    # Match the runtime model and cache locations so the service image contains its model.
    model = WhisperModel(
        os.getenv("WHISPER_MODEL", "tiny"),
        device="cpu",
        compute_type=os.getenv("WHISPER_COMPUTE_TYPE", "int8"),
        cpu_threads=max(1, min(4, int(os.getenv("WHISPER_CPU_THREADS", "2")))),
        download_root=str(main._MODEL_ROOT / "whisper"),
    )
    del model
    gc.collect()
    for voice in main._VOICE_FILES:
        main._ensure_voice_files(voice)
    print("Downloaded Whisper tiny and the configured Piper voices.")


if __name__ == "__main__":
    main_download()
