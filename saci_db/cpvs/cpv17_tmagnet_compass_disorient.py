from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (CyberComponentBase,Controller, Motor)
from saci.modeling.device.compass import CompassSensor
from saci.modeling.device.motor.steering import Steering
from saci.modeling.state import GlobalState

from saci_db.vulns.compass_spoofing import CompassSpoofingVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.magnetic_attack_signal import MagneticAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.communication import ExternalInput

class TemporaryCompassSpoofingCPV(CPV):
    
    NAME = "The Temporary Magnet-on-the-compass-DoS CPV"
    
    def __init__(self):
        super().__init__(
            required_components=[
                CompassSensor(),
                Controller(),
                Steering(),
                Motor(),],
            entry_component=CompassSensor(),
            exit_component=Motor(),
            
            vulnerabilities=[CompassSpoofingVuln(), ControllerIntegrityVuln],

            goals = [],

            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any", 
                "Environment": "Any", 
                "RemoteController": "On", 
                "CPSController": "Moving",
                "Operating mode": "Mission",},

            attack_requirements = ["Magnet with adequate shapes and dimensions"],
            attack_vectors = [BaseAttackVector(name="Magnetic Interference", 
                                               signal=MagneticAttackSignal(src=ExternalInput(), dst=CompassSensor()),
                                               required_access_level="Physical",
                                               configuration={"duration": "10 sec"},
                                                )],  
            attack_impacts = [BaseAttackImpact(category='Loss of control',
                                               description='CPS drives in circles without stopping'),
                              BaseAttackImpact(category='Loss of control',
                                               description='over/under steer of the desired turning angle'),],

            exploit_steps=[
            "Prepare a powerful magnet with adequate shapes and dimensions.",
            "Install the magnet on top of the compass.",
            "Until observing change in the compass readings, keep doing the following: Point the CPS device at a different direction then install the magnet on top of the compass."
            "Leave the magnet in place for at least 10 seconds.",
            "Remove the magnet.",
            "Rotate the CPS 45 degrees in either direction and observe that the compass readings do not significantly change as the CPS rotates."
            "Rotate the CPS 180 degrees from the original heading. The compass readings should either not significantly change or not change until near 180 degrees."
            ],

            associated_files = [],
            reference_urls = ["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV007"],
        )

    def is_possible_path(self, path: List[CyberComponentBase]):
        for required in self.required_components:
            if not any(map(lambda p: isinstance(p, required), path)):
                return False
        return True

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
