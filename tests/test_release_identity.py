"""Release metadata must stay consistent across every public surface."""

from importlib.metadata import version

import aisec
import freshpatch
from aisec import ScanReport
from aisec.reports import sarif_report
from patchwork_api.app import create_app
from patchwork_common import PROJECT_URL, __version__


def test_release_version_and_project_url_are_canonical() -> None:
    assert version("patchwork-security-lab") == __version__
    assert aisec.__version__ == __version__
    assert freshpatch.__version__ == __version__
    assert create_app().version == __version__

    report = ScanReport(".", "source").finish()
    assert report.to_dict()["tool"]["version"] == __version__
    sarif = sarif_report(report)
    assert f'"version": "{__version__}"' in sarif
    assert f'"informationUri": "{PROJECT_URL}"' in sarif
