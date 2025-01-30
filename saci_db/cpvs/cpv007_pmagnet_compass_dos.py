from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (Serial, Controller, PWMChannel, Motor)
from saci.modeling.device.sensor import CompassSensor
from saci.modeling.device.motor.steering import Steering
from saci.modeling.state import GlobalState

from saci_db.vulns.compass_spoofing_vuln import CompassSpoofingVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.magnetic_attack_signal import MagneticAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.communication import ExternalInput

class CompassPermanentSpoofingCPV(CPV):
    
    NAME = "The Permanent Magnetic Interference on Compass"
    
    def __init__(self):
        super().__init__(
            required_components=[
                CompassSensor(),
                Controller(),
                Controller(),
                PWMChannel(),
                Steering(),],
            entry_component=CompassSensor(),
            exit_component=Motor(),
            
            vulnerabilities=[CompassSpoofingVuln(), ControllerIntegrityVuln()],

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
            attack_vectors = [BaseAttackVector(name="Magnetic Signals Interference", 
                                               signal=MagneticAttackSignal(src=ExternalInput(), dst=CompassSensor()),
                                               required_access_level="Physical",
                                               configuration={"duration": "permanent"},
                                                )],  
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

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
