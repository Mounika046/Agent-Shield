import os
from pathlib import Path
from typing import Optional


PROMPT_DIR = Path(__file__).resolve().parent
DEFAULT_INPUT_PROMPT_PATH = PROMPT_DIR / "prompts_input.txt"
DEFAULT_OUTPUT_PROMPT_PATH = PROMPT_DIR / "prompts_output.txt"
DEFAULT_DETAILED_OUTPUT_PROMPT_PATH = PROMPT_DIR / "prompts_output_detailed.txt"
DEFAULT_DEVELOPER_OUTPUT_PROMPT_PATH = PROMPT_DIR / "prompts_output_developer.txt"
DEFAULT_PROMPT_PATH = DEFAULT_INPUT_PROMPT_PATH


def load_agent_prompt() -> str:
    prompt_path = Path(os.getenv("AGENT_CONTROL_PROMPT_PATH", str(DEFAULT_PROMPT_PATH)))
    try:
        return prompt_path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _load_prompt(env_name: str, default_path: Path) -> str:
    prompt_path = Path(os.getenv(env_name, str(default_path)))
    try:
        return prompt_path.read_text(encoding="utf-8")
    except OSError:
        return ""


def prompt_status() -> dict[str, object]:
    input_path = Path(os.getenv("AGENT_INPUT_PROMPT_PATH", str(DEFAULT_INPUT_PROMPT_PATH)))
    output_path = Path(os.getenv("AGENT_OUTPUT_PROMPT_PATH", str(DEFAULT_OUTPUT_PROMPT_PATH)))
    return {
        "input_prompt_path": str(input_path),
        "input_prompt_loaded": input_path.is_file(),
        "output_prompt_path": str(output_path),
        "output_prompt_loaded": output_path.is_file(),
    }


def load_input_prompt() -> str:
    return _load_prompt("AGENT_INPUT_PROMPT_PATH", DEFAULT_INPUT_PROMPT_PATH) or load_agent_prompt()


def load_output_prompt(mode: Optional[str] = None) -> str:
    normalized_mode = str(mode or "").strip().lower()
    if normalized_mode == "detailed":
        return (
            _load_prompt("AGENT_OUTPUT_PROMPT_DETAILED_PATH", DEFAULT_DETAILED_OUTPUT_PROMPT_PATH)
            or _load_prompt("AGENT_OUTPUT_PROMPT_PATH", DEFAULT_OUTPUT_PROMPT_PATH)
            or load_agent_prompt()
        )
    if normalized_mode == "developer":
        return (
            _load_prompt("AGENT_OUTPUT_PROMPT_DEVELOPER_PATH", DEFAULT_DEVELOPER_OUTPUT_PROMPT_PATH)
            or _load_prompt("AGENT_OUTPUT_PROMPT_PATH", DEFAULT_OUTPUT_PROMPT_PATH)
            or load_agent_prompt()
        )
    return _load_prompt("AGENT_OUTPUT_PROMPT_PATH", DEFAULT_OUTPUT_PROMPT_PATH) or load_agent_prompt()
