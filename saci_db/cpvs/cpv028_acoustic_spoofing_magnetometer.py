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
    
    NAME = "The Acoustic Spoofing Attack on Magnetometer Sensors"
    
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
                "OperatingMode": "Manual or Mission",
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
                "TA1 Exploit Steps",
                    "Reverse-engineer the CPS firmware to determine if sensor fusion or filtering mechanisms exist for magnetometer data.",
                    "Identify whether the firmware fully trusts the raw magnetometer data or applies any verification before use.",
                    "Analyze the PID control logic to assess how fluctuations in magnetometer readings propagate to motor actuation.",
                
                "TA2 Exploit Steps",
                    "Implement a simulation of MEMS magnetometer response to acoustic interference.",
                    "Inject synthetic acoustic noise into the control loop and measure PID controller response.",
                    "Simulate how abnormal magnetometer outputs propagate through the CPS system.",
                
                "TA3 Exploit Steps",
                    "Determine the Resonant Frequency of the Magnetometer Sensor installed on the CPS.",
                    "Point the spoofing audio source device towards the CPS and play the sound noise.",
                    "Observe the CPS's erratic movements in response to spoofed sensor readings.",
            ],
            
            associated_files=[],
            reference_urls=["https://www.blackhat.com/docs/us-17/thursday/us-17-Wang-Sonic-Gun-To-Smart-Devices-Your-Devices-Lose-Control-Under-Ultrasound-Or-Sound.pdf"],
        )
        
    def in_goal_state(self, state: GlobalState):
        pass