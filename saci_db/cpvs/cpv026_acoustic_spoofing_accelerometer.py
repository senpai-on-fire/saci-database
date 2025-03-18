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
                "OperatingMode": "Manual or Mission",
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
                    description="CPS behaves in response to spoofed sensor values."
                )
            ],
            
            exploit_steps = [
                "TA1 Exploit Steps",
                    "Construct the acoustic signal with necessary modulation (amplitude, frequency, phase shifting) to achieve the desired impact.",
                    "Reverse-engineer the CPS firmware to determine if sensor fusion or filtering mechanisms exist for accelerometer data.",
                    "Identify whether the firmware fully trusts the raw accelerometer data or applies verification before use.",
                    "Analyze the PID control logic to assess how fluctuations in accelerometer readings propagate to motor actuation.",
                
                "TA2 Exploit Steps",
                    "Implement a simulation of MEMS accelerometer response to acoustic interference.",
                    "Run CPS simulation to analyze how manipulated accelerometer readings translate to control instability in the CPS device.",
                    "Collaborate with TA2 to determine the desired control impact (e.g., altitude drop, drift, erratic movement).",    
                
                "TA3 Exploit Steps",
                    "Use imaging tools to catalog all components on the CPS.",
                    "Identify if an IMU containing an accelerometer is present.",
                    "Mount the accelerometer (or CPS) in a vibration-free environment and measure output under a frequency sweep (e.g., 20Hz to 30kHz).",
                    "Identify the resonant frequency at which acceleration output deviates most from the true value.",
                    "Position an ultrasonic transducer/speaker near the CPS and emit the resonant frequency.",
                    "Alternatively, attach a miniature acoustic transducer to the CPS chassis/controller board to introduce vibrations.",
                    "Log accelerometer sensor data before, during, and after the attack.",
                    "Analyze the CPS's physical response using external tracking and onboard telemetry."
                ],

            associated_files=[],
            reference_urls=["https://dl.acm.org/doi/pdf/10.1145/3560905.3568532",
                            "https://www.blackhat.com/docs/us-17/thursday/us-17-Wang-Sonic-Gun-To-Smart-Devices-Your-Devices-Lose-Control-Under-Ultrasound-Or-Sound.pdf"],
        )
        
    def in_goal_state(self, state: GlobalState):
        pass