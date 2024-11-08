import pytest

from open_mpic_core.common_domain.remote_perspective import RemotePerspective
from open_mpic_core.mpic_dcv_checker.mpic_dcv_checker import MpicDcvChecker


# noinspection PyMethodMayBeStatic
@pytest.mark.integration
class TestDcvCheckerWithResolver:
    @classmethod
    def setup_class(cls):
        perspective: RemotePerspective = RemotePerspective(rir='arin', code='us-east-4')
        cls.dcv_checker: MpicDcvChecker = MpicDcvChecker(perspective)

    @pytest.mark.skip(reason='Not implemented yet')
    def dcv_check__should_follow_redirects_and_return_list_in_response_details(self):
        pass
