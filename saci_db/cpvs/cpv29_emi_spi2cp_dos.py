from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (IMU, Controller, Motor)
from saci.modeling.device import Serial
from saci.modeling.state import GlobalState

from saci_db.vulns.Serial_spoofing_vuln import SerialSpoofingVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.magnetic_attack_signal import MagneticAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.communication import ExternalInput

class SerialIMUSpoofingCPV(CPV):
    
    NAME = "IMU Spoofing using EMI"
    
    def __init__(self):
        super().__init__(
            required_components=[
                Serial(),
                IMU(),
                Controller(),
                Motor(),],
            entry_component=Serial(),
            exit_component=Motor(),
            
            vulnerabilities=[SerialSpoofingVuln(), ControllerIntegrityVuln()],

            goals = [],

            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any", 
                "Environment": "Any", 
                "RemoteController": "On", 
                "CPSController": "Moving",
                "Operating mode": "Mission",},

            attack_requirements = ["RF Signal Generators", "Amplifiers", "Near-Field Probes", "Loop Antennas or Coils "],
            attack_vectors = [BaseAttackVector(name="Electromagnetic Signals Interference", 
                                               signal=MagneticAttackSignal(src=ExternalInput(), dst=Controller()),
                                               required_access_level="Remote",
                                               configuration={"duration": "permanent"},
                                                )],  
            attack_impacts = [BaseAttackImpact(category='Denial of service',
                                               description='Motor stops responding to legititame PWM commands')],

            exploit_steps=["Determine the specific model of the drone's control unit using optical analysis",
            "Acquire an identical model of the target control unit for testing purposes.",
            "Use a near-field electromagnetic compatibility (EMC) scanner to measure the EMI emissions of the control unit.",
            "Identify the specific frequency at which the control unit is most susceptible to EMI-induced distortions.",
            "Utilize an RF signal generator to produce a continuous wave (CW) signal at the identified susceptible frequency.",
            "Connect the signal generator to a power amplifier to ensure the signal has sufficient strength to affect the target.",
            "Attach a monopole antenna to the amplifier to direct the EMI towards the drone's control unit.",
            "Place the antenna in proximity to the drone's control unit, ensuring it is within the effective range for EMI injection.",
            "Ensure there are no obstacles between the antenna and the control unit to maximize the effectiveness of the EMI signal.",
            "Activate the RF signal generator to emit the EMI at the susceptible frequency.",
            "Monitor the drone's behavior to observe any anomalies or disruptions in its operation.",
            "Record the drone's responses to the EMI injection, noting any loss of control, erratic movements, or crashes.",
            "Adjust the power levels and positioning as necessary to achieve the desired disruptive effect."            
            ],

            associated_files = [],
            reference_urls = ["https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_f616_paper.pdf"],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass