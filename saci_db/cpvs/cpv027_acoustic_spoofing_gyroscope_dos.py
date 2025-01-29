from typing import List
from saci.modeling import CPV

from saci.modeling.device import Gyroscope, Serial, PWMChannel, ESC, MultiCopterMotor
from saci_db.devices.px4_quadcopter_device import PX4Controller

from saci_db.vulns.gyroscope_spoofing_vuln import GyroscopeSpoofingVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln

from saci.modeling.communication import ExternalInput
from saci.modeling.state import GlobalState

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.acoustic_attack_signal import AcousticAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

class AcousticSpoofingGyroscopeCPV(CPV):
    
    NAME = "The Acoustic Spoofing on Gyroscope Sensors"
    
    def __init__(self):
        super().__init__(
            required_components=[
                Gyroscope(),
                Serial(),            
                PX4Controller(),   
                PWMChannel(),  
                ESC(),
                MultiCopterMotor(), 
            ],
            entry_component=Gyroscope(),
            exit_component=MultiCopterMotor(),
            
            vulnerabilities=[GyroscopeSpoofingVuln(), ControllerIntegrityVuln()],
            
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
                        dst=Gyroscope(),
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
            reference_urls=["https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-son.pdf",
                            "https://www.blackhat.com/docs/us-17/thursday/us-17-Wang-Sonic-Gun-To-Smart-Devices-Your-Devices-Lose-Control-Under-Ultrasound-Or-Sound.pdf"],
        )
        
    def in_goal_state(self, state: GlobalState):
        pass