from typing import List
from saci.modeling import CPV

from saci.modeling.device import Gyroscope, Serial, PWMChannel, ESC, MultiCopterMotor, Telemetry
from saci_db.devices.px4_quadcopter_device import PX4Controller

from saci_db.vulns.gyroscope_spoofing_vuln import GyroscopeSpoofingVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln

from saci.modeling.communication import ExternalInput
from saci.modeling.state import GlobalState

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.acoustic_attack_signal import AcousticAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

class AcousticSpoofingGyroscopeCPV(CPV):
    
    NAME = "The Acoustic Spoofing Attack on Gyroscope Sensors"
    
    def __init__(self):
        super().__init__(
            required_components=[
                Gyroscope(),
                Serial(),     
                Telemetry(),       
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
                "OperatingMode": "Manual or Mission",
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
                    required_access_level="close proximity or physical",
                    configuration={
                        "duration": "Permanent",
                        "frequency": "Resonant Frequency",
                    },
                )
            ],
            attack_impacts=[
                BaseAttackImpact(
                    category="Control Manipulation",
                    description="CPS moves erratically."
                )
            ],
            
            exploit_steps = [
                "TA1 Exploit Steps",
                    "Reverse-engineer the CPS firmware to determine if sensor fusion or filtering mechanisms exist for gyroscope data.",
                    "Identify whether the firmware fully trusts the raw gyroscope data or applies any verification before use.",
                    "Analyze the PID control logic to assess how fluctuations in gyroscope readings propagate to motor actuation.",
                
                "TA2 Exploit Steps",
                    "Implement a simulation of MEMS gyroscope response to acoustic interference.",
                    "Inject synthetic acoustic noise into the control loop and measure PID controller response.",
                    "Simulate how abnormal gyroscope outputs propagate through the CPS system.",     
                    "Report the findings to TA3 to conduct the experiments on the physical CPS device",
                
                "TA3 Exploit Steps",
                    "Use imaging tools and other techniques to catalog all components on the CPS.",
                    "Identify if an IMU containing a gyroscope is present.",
                    "Mount the MEMS gyroscope (or CPS) in a vibration-free environment and measure output when exposed to an acoustic frequency sweep (e.g., 20Hz to 30kHz).",
                    "Observe gyroscope sensor output for spikes and increased standard deviation to detect resonance-induced errors.",
                    "Identify the resonant frequency at the point of maximum deviation from the true value.",
                    "Position an ultrasonic transducer/speaker near the CPS and emit the resonant frequency.",
                    "Log gyroscope sensor data before, during, and after the attack.",
                    "Analyze the CPS's physical response using external tracking and onboard telemetry."
                ],

            associated_files=[],
            reference_urls=["https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-son.pdf",
                            "https://www.blackhat.com/docs/us-17/thursday/us-17-Wang-Sonic-Gun-To-Smart-Devices-Your-Devices-Lose-Control-Under-Ultrasound-Or-Sound.pdf"],
        )
        
    def in_goal_state(self, state: GlobalState):
        pass