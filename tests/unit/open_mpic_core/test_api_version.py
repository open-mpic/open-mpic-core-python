import tomllib
from pathlib import Path

import pytest

from open_mpic_core.__about__ import __api_version__


# noinspection PyMethodMayBeStatic
class TestApiVersion:
    """
    Guards the sync between the authoritative __api_version__ declared in __about__.py and the
    tool.api.spec_version value mirrored in pyproject.toml for external tooling.
    """

    def api_version__should_match_spec_version_declared_in_pyproject(self):
        pyproject_path = Path(__file__).parents[3] / "pyproject.toml"
        with pyproject_path.open(mode="rb") as file:
            pyproject = tomllib.load(file)
        assert pyproject["tool"]["api"]["spec_version"] == __api_version__


if __name__ == "__main__":
    pytest.main()
