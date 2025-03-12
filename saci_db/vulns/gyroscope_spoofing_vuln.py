import os.path

from clorm import Predicate

from saci.modeling import SpoofingVulnerability

from saci.modeling.device import Device
from saci.modeling.device.sensor import Gyroscope, GyroscopeHWPackage 

from saci.modeling.communication import AuthenticatedCommunication, UnauthenticatedCommunication, ExternalInput
from saci.modeling.attack_vector import BaseAttackVector, AcousticAttackSignal, MagneticAttackSignal
from saci.modeling.comp_effect import BaseCompEffect

# Predicate to define formal reasoning logic for Gyroscope spoofing attacks
class GyroscopeSpoofingPred(Predicate):
    pass

class GyroscopeSpoofingVuln(SpoofingVulnerability):
    def __init__(self):
        super().__init__(
            # The Gyroscope component vulnerable to spoofing attacks
            component=Gyroscope(),
            # Input: Authenticated communication representing spoofed signals from an external source
            _input=AuthenticatedCommunication(src=ExternalInput()),
            # Output: Authenticated communication representing erroneous navigation decisions caused by Gyroscope data
            output=AuthenticatedCommunication(),
            # Predicate for formal reasoning about Gyroscope spoofing
            attack_ASP=GyroscopeSpoofingPred,
            # Logic rules for evaluating the Gyroscope spoofing vulnerability
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'gyroscope_spoofing.lp'),
            # List of Associated CWEs:
            associated_cwe = [
                "CWE-346: Origin Validation Error",
                "CWE-290: Authentication Bypass by Capture-replay",
                "CWE-20: Improper Input Validation",
                "CWE-693: Protection Mechanism Failure",
                "CWE-1188: Insecure Default Initialization of Resource",
                "CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer",
                "CWE-662: Improper Synchronization"
            ],
            attack_vectors_exploits = [
                {
                    "attack_vector": [
                        BaseAttackVector(
                            name="Acoustic Signal Interference",
                            signal=AcousticAttackSignal(
                                src=ExternalInput(),
                                dst=Gyroscope(),
                                modality="audio",
                            ),
                            required_access_level="close proximity or physical",
                            configuration={
                                "attack_method": "Emit acoustic interference targeting the gyroscope sensor",
                                "equipment": "Speaker or Ultrasonic Sound Source",
                                "target_frequency": "Resonant Frequency",
                            },
                        )
                    ],
                    "related_cpv": [
                        "AcousticSpoofingGyroscopeCPV"
                    ],
                    "comp_attack_effect": [
                        BaseCompEffect(
                            category='Integrity',
                            description='Acoustic interference can cause unauthorized device movement and navigation errors through signal data tampering'
                        )
                    ],
                    "exploit_steps": [
                        "Reverse-engineer the CPS firmware to determine if sensor fusion or filtering mechanisms exist for gyroscope data.",
                        "Identify whether the firmware fully trusts the raw gyroscope data or applies any verification before use.",
                        "Analyze the PID control logic to assess how fluctuations in gyroscope readings propagate to motor actuation."
                    ],
                    "reference_urls": [
                        "https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-son.pdf",
                        "https://www.blackhat.com/docs/us-17/thursday/us-17-Wang-Sonic-Gun-To-Smart-Devices-Your-Devices-Lose-Control-Under-Ultrasound-Or-Sound.pdf"
                    ]
                },
                {
                    "attack_vector": [
                        BaseAttackVector(
                            name="Electromagnetic Signal Interference",
                            signal=MagneticAttackSignal(
                                src=ExternalInput(),
                                dst=Gyroscope(),
                            ),
                            required_access_level="Proximity",
                            configuration={
                                "attack_method": "Inject electromagnetic interference into the gyroscope's communication channel",
                                "equipment": "High-power EMI emitter (~30W for 10cm, ~300-500KW for 100 m)",
                                "target_frequency": "Specific to the controller used",
                            },
                        )
                    ],
                    "related_cpv": [
                        "GyroscopeEMIChannelDisruptionCPV"
                    ],
                    "comp_attack_effect": [
                        BaseCompEffect(
                            category='Denial of Service',
                            description='Electromagnetic interference can cause inaccurate flight paths and navigation failure through signal data tampering'
                        )
                    ],
                    "exploit_steps": [
                        "Model the impact of fault injection into the serial communication channel on the drone flight to verify the validity of the attack.",
                        "Simulate the impact of fault injection into the serial communication channel on the drone flight to verify the validity of the attack.",
                        "Record all drone physical properties, including weight, dimensions, center of gravity, etc.",
                        "Identify the gyroscope's serial communication channel protocol and transmission frequency.",
                        "Use imaging tools to catalog all components on the CPS.",
                        "Identify if an IMU containing a gyroscope is present.",
                        "Mount the MEMS gyroscope (or CPS) in a vibration-free environment and measure output when exposed to an acoustic frequency sweep.",
                        "Observe gyroscope sensor output for spikes and increased standard deviation to detect resonance-induced errors.",
                        "Identify the resonant frequency at the point of maximum deviation from the true value.",
                        "Position an ultrasonic transducer/speaker near the CPS and emit the resonant frequency.",
                        "Log gyroscope sensor data before, during, and after the attack.",
                        "Analyze the CPS's physical response using external tracking and onboard telemetry."
                    ],
                    "reference_urls": [
                        "https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_f616_paper.pdf"
                    ]
                }
            ]
        )

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            if isinstance(comp, Gyroscope) and comp.chip_type == "MEMS":
                return True

            if isinstance(comp, GyroscopeHWPackage):
                vuln_sensor_list = ['L3G4200D', 'L3GD20', 'LSM330', 'LPR5150AL', 'LPY503AL', 'MPU3050', 'MPU6000', 'MPU6050', 'MPU6500', 'MPU9150', 'IMU3000', 'ITG3200', 'IXZ650', 'ADXRS610', 'ENC-03MB']
                if comp.chip_name in vuln_sensor_list:
                    return True
        