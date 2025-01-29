from typing import List
from saci.modeling.device import ESC, Magnetometer, Serial, PWMChannel, ESC, MultiCopterMotor
from saci_db.devices.px4_quadcopter_device import PX4Controller
from saci.modeling import CPV

from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln
from saci_db.vulns.magnetometer_spoofing_vuln import MagnetometerSpoofingVuln

from saci.modeling.communication import ExternalInput
from saci.modeling.state import GlobalState

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.acoustic_attack_signal import AcousticAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact


class AcousticSpoofingMagnetometerCPV(CPV):
    
    NAME = "The Acoustic Spoofing on Magnetometer Sensors"
    
    def __init__(self):
        super().__init__(
            required_components=[
                Magnetometer(),
                Serial() ,          
                PX4Controller(),   
                PWMChannel(),  
                ESC(),
                MultiCopterMotor(), 
            ],
            entry_component=Magnetometer(),
            exit_component=MultiCopterMotor(),
            
            vulnerabilities=[MagnetometerSpoofingVuln(), ControllerIntegrityVuln()],
            
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
                        dst=Magnetometer(),
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
                "Determine the Resonant Frequency of the Magnetometer Sensor installed on the CPS.",
                "Point the spoofing audio source device towards the CPS and play the sound noise.",
                "Observe the CPS's erratic movements in response to spoofed sensor readings.",
            ],
            
            associated_files=[],
            reference_urls=["https://www.blackhat.com/docs/us-17/thursday/us-17-Wang-Sonic-Gun-To-Smart-Devices-Your-Devices-Lose-Control-Under-Ultrasound-Or-Sound.pdf"],
        )
        
    def in_goal_state(self, state: GlobalState):
        pass