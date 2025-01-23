from typing import List
from saci.modeling.device import CyberComponentBase, ESC, Motor, Accelerometer, MultiCopterMotor
from saci_db.devices.px4_quadcopter_device import PX4Controller
from saci.modeling import CPV
from saci_db.vulns.accelerometer_spoofing_vuln import AccelerometerSpoofingVuln
from saci_db.vulns.px4_controller_integerity_vuln import PX4ControllerIntegrityVuln
from saci.modeling.communication import ExternalInput
from saci.modeling.state import GlobalState
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.image_attack_signal import AcousticAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact


class AcousticAccelerometerCPV(CPV):
    
    NAME = "The Acoustic Accelerometer CPV"
    
    def __init__(self):
        super().__init__(
            required_components=[
                Accelerometer(),
                PX4Controller(),
                ESC(),
                MultiCopterMotor(),
            ],
            entry_component=Accelerometer(),
            exit_component=MultiCopterMotor(),
            
            vulnerabilities=[AccelerometerSpoofingVuln(), PX4ControllerIntegrityVuln()],
            
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
                        dst=AccelerometerSpoofingVuln().component,
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
            reference_urls=["https://dl.acm.org/doi/pdf/10.1145/3560905.3568532"],
        )
        
    def in_goal_state(self, state: GlobalState):
        pass