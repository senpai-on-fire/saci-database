from typing import List
from saci.modeling import CPV

from saci.modeling.device import Accelerometer,Serial, PWMChannel, ESC, MultiCopterMotor

from saci_db.devices.px4_quadcopter_device import PX4Controller
from saci_db.vulns.accelerometer_spoofing_vuln import AccelerometerSpoofingVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln

from saci.modeling.communication import ExternalInput
from saci.modeling.state import GlobalState

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.acoustic_attack_signal import AcousticAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

class AcousticSpoofingAccelerometerCPV(CPV):
    
    NAME = "The Acoustic Spoofing Attack on Accelerometer Sensors"
    
    def __init__(self):
        super().__init__(
            required_components=[
                Accelerometer(),
                Serial(),           
                PX4Controller(),   
                PWMChannel(),  
                ESC(),
                MultiCopterMotor(), 
            ],
            entry_component=Accelerometer(),
            exit_component=MultiCopterMotor(),
            
            vulnerabilities=[AccelerometerSpoofingVuln(), ControllerIntegrityVuln()],
            
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
                        dst=Accelerometer(),
                        modality="audio",
                    ),
                    required_access_level="Physical",
                    configuration={"duration": "Permanent"},
                )
            ],
            attack_impacts=[
                BaseAttackImpact(
                    category="Control Manipulation",
                    description="CPS behaves in response to spoofed sensor values."
                )
            ],
            
            exploit_steps = [
                "Determine the resonant frequency of the accelerometer sensor installed on the CPS.",
                "Generate an acoustic signal modulated with the desired false sensor output.",
                "Direct the acoustic source device toward the CPS and emit the modulated signal.",
                "Observe the CPS's behavior in response to the spoofed accelerometer readings.",
            ],
            
            associated_files=[],
            reference_urls=["https://dl.acm.org/doi/pdf/10.1145/3560905.3568532",
                            "https://www.blackhat.com/docs/us-17/thursday/us-17-Wang-Sonic-Gun-To-Smart-Devices-Your-Devices-Lose-Control-Under-Ultrasound-Or-Sound.pdf"],
        )
        
    def in_goal_state(self, state: GlobalState):
        pass