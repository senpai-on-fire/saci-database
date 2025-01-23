from typing import List
from saci.modeling.device import CyberComponentBase, ESC, Motor, Gyroscope, MultiCopterMotor
from saci_db.devices.px4_quadcopter_device import PX4Controller
from saci.modeling import CPV
from saci_db.vulns.rocking_the_drone_vuln import RockingDronesVuln
from saci_db.vulns.px4_controller_integerity_vuln import PX4ControllerIntegrityVuln
from saci.modeling.communication import ExternalInput
from saci.modeling.state import GlobalState
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.image_attack_signal import AcousticAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact


class AcousticGyroscopeCPV(CPV):
    
    NAME = "The Acoustic Gyroscope CPV"
    
    def __init__(self):
        super().__init__(
            required_components=[
                Gyroscope(),
                PX4Controller(),
                ESC(),
                MultiCopterMotor(),
            ],
            entry_component=Gyroscope(),
            exit_component=MultiCopterMotor(),
            
            vulnerabilities=[RockingDronesVuln(), PX4ControllerIntegrityVuln()],
            
            goals=[],
            
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "None",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "None",
                "Operating mode": "Hold",
            },
            
            attack_requirements=["Speaker or Ultrasonic Sound Source"],
            attack_vectors=[
                BaseAttackVector(
                    name="Acoustic Spoofing Signal Injection",
                    signal=AcousticAttackSignal(
                        src=ExternalInput(),
                        dst=RockingDronesVuln().component,
                        modality="audio",
                    ),
                    required_access_level="Physical",
                    configuration={"duration": "Permanent"},
                )
            ],
            attack_impacts=[
                BaseAttackImpact(
                    category="Control Manipulation",
                    description="CPS moves erratically."
                )
            ],
            
            exploit_steps=[
                "Determine the Resonant Frequency of the Gyroscope Sensor installed on the CPS.",
                "Point the spoofing audio source device towards the CPS and play the sound noise.",
                "Observe the CPS's erratic movements in response to spoofed sensor readings.",
            ],
            
            associated_files=[],
            reference_urls=["https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-son.pdf"],
        )
        
    def in_goal_state(self, state: GlobalState):
        pass