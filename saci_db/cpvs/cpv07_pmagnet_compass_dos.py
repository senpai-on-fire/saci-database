from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (CyberComponentBase,Controller, Motor)
from saci.modeling.device.compass import CompassSensor
from saci.modeling.device.motor.steering import Steering
from saci.modeling.state import GlobalState

from saci_db.vulns.compass_spoofing import CompassSpoofingVuln
from saci_db.vulns.weak_data_integrity_vuln import WeakDataIntegrityVuln

from saci.modeling.attack.magnetic_attack_signal import MagneticAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

class CompassInterferenceCPV(CPV):
    
    NAME = "The magnet-on-the-compass-DoS CPV"
    
    def __init__(self):
        super().__init__(
            required_components=[
                CompassSensor(),
                Controller(),
                Steering(),
                Motor(),],
            entry_component=CompassSensor(),
            exit_component=Motor(),
            
            vulnerabilities=[CompassSpoofingVuln(), WeakDataIntegrityVuln()],

            goals = [],

            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any", 
                "Environment": "Any", 
                "RemoteController": "On", 
                "CPSController": "Moving",
                "Operating mode": "Mission",},

            attack_vectors = [MagneticAttackSignal(src='magnet', dst=CompassSpoofingVuln().component)], 
            attack_requirements = "Powerful magnet with adequate shapes and dimensions",
            attack_impacts = [BaseAttackImpact(category='Loss of control',
                                               description='CPS drives in circles without stopping')],

            exploit_steps=[
            "Prepare a powerful magnet with adequate shapes and dimensions.",
            "Install the magnet on top of the compass.",
            "Until observing change in the compass readings, keep doing the following: Point the CPS device at a different direction then install the magnet on top of the compass.",
            "Rotate the CPS device and observe that the compass readings do not significantly change as the CPS rotates.",
            ],

            associated_files = [],
            reference_urls = ["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV006"],
        )

    def is_possible_path(self, path: List[CyberComponentBase]):
        required_components = [CompassSensor, Controller, Steering, Motor]
        for required in required_components:
            if not any(map(lambda p: isinstance(p, required), path)):
                return False
        return True

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
