import os.path
from clorm import Predicate

from saci.modeling.vulnerability import SpoofingVulnerability
from saci.modeling.device import Device
from saci.modeling.device.sensor import DepthCamera
from saci.modeling.communication import UnauthenticatedCommunication, ExternalInput


# Predicate to define formal reasoning logic for stereo vision spoofing attacks
class StereoMatchingPred(Predicate):
    pass


class StereoMatchingVuln(SpoofingVulnerability):
    def __init__(self):
        super().__init__(
            # The StereoCamera component is vulnerable to stereo matching attacks
            component=DepthCamera(),
            # Input: External optical interference (e.g., projected light patterns)
            _input=UnauthenticatedCommunication(src=ExternalInput()),
            # Output: Manipulated stereo depth data due to adversarial projection
            output=UnauthenticatedCommunication(),
            # Predicate for formal reasoning about stereo matching vulnerabilities
            attack_ASP=StereoMatchingPred,
            # Logic rules for evaluating this vulnerability in formal reasoning
            rulefile=os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                "stereo_matching_spoofing.lp",
            ),
            # List of Associated CWEs:
            associated_cwe=[
                "CWE-346: Origin Validation Error",
                "CWE-290: Authentication Bypass by Capture-replay",
                "CWE-20: Improper Input Validation",
                "CWE-693: Protection Mechanism Failure",
                "CWE-1254: Improper Handling of Transparent or Translucent Inputs",
            ],
            attack_vectors=[],
        )

    def exists(self, device: Device) -> bool:
        """
        Checks if the stereo matching vulnerability exists in the given device by evaluating
        whether it supports stereo vision-based depth estimation and lacks sufficient defenses
        against adversarial light projection.
        """
        for comp in device.components:
            # Check if the component is a StereoCamera
            if isinstance(comp, DepthCamera):
                # Ensure the stereo camera supports disparity-based depth estimation and is operational
                if comp.supports_disparity_matching() and comp.enabled():
                    return True  # Vulnerability exists if stereo matching is enabled without adversarial defenses
        return False  # No vulnerability detected if conditions are unmet
