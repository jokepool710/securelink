from pathlib import Path

from app.config import PROJECT_ROOT, Settings


def test_settings_load_dotenv_from_the_repository_root():
    assert Path(Settings.model_config["env_file"]) == PROJECT_ROOT / ".env"
