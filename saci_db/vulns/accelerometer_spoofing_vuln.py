import os.path

from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling import SpoofingVulnerability
from saci.modeling.device import Device
from saci.modeling.device.sensor.accelerometer import Accelerometer, AccelerometerHardware
from saci.modeling.communication import UnauthenticatedCommunication, AuthenticatedCommunication, ExternalInput
from saci.modeling.attack_vector import BaseAttackVector, AcousticAttackSignal, MagneticAttackSignal
from saci.modeling.comp_effect import BaseCompEffect

# Predicate to define the formal reasoning logic for the accelerometer spoofing attack
class AccelerometerSpoofingPred(Predicate):
    pass

class AccelerometerSpoofingVuln(SpoofingVulnerability):
    def __init__(self):
        super().__init__(
            # The accelerometer component that is vulnerable to spoofing attacks
            component=Accelerometer(),
            # Input to the spoofing attack: Authenticated, spoofed accelerometer signals
            _input=AuthenticatedCommunication(src=ExternalInput()),
            # Output: navigation decisions corrupted by the spoofed accelerometer signals
            output=AuthenticatedCommunication(),
            # Predicate for reasoning about accelerometer spoofing attacks
            attack_ASP=AccelerometerSpoofingPred,
            # Logic rules for evaluating this vulnerability
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'accelerometer_spoofing.lp'),
            # List of associated CWEs
            associated_cwe=[
                "CWE-346: Origin Validation Error",
                "CWE-290: Authentication Bypass by Capture-replay",
                "CWE-20: Improper Input Validation",
                "CWE-1188: Insecure Default Initialization of Resource",
                "CWE-693: Protection Mechanism Failure"
            ],
            attack_vectors_exploits = [
                {
                    "attack_vector": [
                        BaseAttackVector(
                            name="Acoustic Signal Interference",
                            signal=AcousticAttackSignal(
                                src=ExternalInput(),
                                dst=Accelerometer(),
                                modality="audio",
                            ),
                            required_access_level="close proximity or physical",
                            configuration={
                                "attack_method": "Emit acoustic interference targeting the accelerometer sensor",
                                "equipment": "Speaker or Ultrasonic Sound Source",
                                "target_frequency": "Resonant Frequency",
                            },
                        )
                    ],
                    "related_cpv": [
                        "AcousticSpoofingAccelerometerCPV"
                    ],
                    "comp_attack_effect": [
                        BaseCompEffect(
                            category='Integrity',
                            description='Acoustic interference can cause unauthorized device movement and navigation errors through signal data tampering'
                        )
                    ],
                    "exploit_steps": [
                        "Construct the acoustic signal with necessary modulation (amplitude, frequency, phase shifting) to achieve the desired impact.",
                        "Reverse-engineer the CPS firmware to determine if sensor fusion or filtering mechanisms exist for accelerometer data.",
                        "Identify whether the firmware fully trusts the raw accelerometer data or applies verification before use.",
                        "Analyze the PID control logic to assess how fluctuations in accelerometer readings propagate to motor actuation."
                    ],
                    "reference_urls": [
                        "https://dl.acm.org/doi/pdf/10.1145/3560905.3568532",
                        "https://www.blackhat.com/docs/us-17/thursday/us-17-Wang-Sonic-Gun-To-Smart-Devices-Your-Devices-Lose-Control-Under-Ultrasound-Or-Sound.pdf"
                    ]
                },
                {
                    "attack_vector": [
                        BaseAttackVector(
                            name="Electromagnetic Signal Interference",
                            signal=MagneticAttackSignal(
                                src=ExternalInput(),
                            ),
                            required_access_level="Proximity",
                            configuration={
                                "attack_method": "Inject electromagnetic interference into the accelerometer's communication channel",
                                "equipment": "High-power EMI emitter (~30W for 10cm, ~300-500KW for 100 m)",
                                "target_frequency": "Specific to the controller used",
                            },
                        )
                    ],
                    "related_cpv": [
                        "AccelerometerEMIChannelDisruptionCPV"
                    ],
                    "comp_attack_effect": [
                        BaseCompEffect(
                            category='Denial of Service',
                            description='Electromagnetic interference can cause inaccurate motion detection and navigation errors through signal data tampering'
                        )
                    ],
                    "exploit_steps": [
                        "Model the impact of fault injection into the serial communication channel on the drone flight to verify the validity of the attack.",
                        "Simulate the impact of fault injection into the serial communication channel on the drone flight to verify the validity of the attack.",
                        "Record all drone physical properties, including weight, dimensions, center of gravity, etc.",
                        "Identify the accelerometer's serial communication channel protocol and transmission frequency.",
                        "Use imaging tools to catalog all components on the CPS.",
                        "Identify if an IMU containing an accelerometer is present.",
                        "Mount the accelerometer (or CPS) in a vibration-free environment and measure output under a frequency sweep.",
                        "Identify the resonant frequency at which acceleration output deviates most from the true value.",
                        "Position an ultrasonic transducer/speaker near the CPS and emit the resonant frequency.",
                        "Log accelerometer sensor data before, during, and after the attack.",
                        "Analyze the CPS's physical response using external tracking and onboard telemetry."
                    ],
                    "reference_urls": [
                        "https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_f616_paper.pdf"
                    ]
                }
            ]
        )

    def exists(self, device: Device) -> bool:
        """
        Determines if this device contains a vulnerable accelerometer:
        - The sensor signals are unauthenticated.
        - The accelerometer has a resonant frequency in a feasible attack range (< 40 kHz).
        - The sensor is known to be vulnerable based on prior research.
        - Low damping_ratio or no acoustic isolation makes it susceptible to spoofing.
        """

        # List of accelerometers explicitly mentioned in research as vulnerable
        vuln_sensor_list = [
            "BMI055", "BMI160", "ICM-20690", "MPU6050", "MPU6000", "LSM6DSL"
        ]

        for comp in device.components:
            # 1) Check if the component is an unauthenticated hardware accelerometer
            if isinstance(comp, AccelerometerHardware) and not comp.authenticated:
                # 2) If the sensor's model is in the known vulnerable list, return True immediately
                if hasattr(comp, "chip_name") and comp.chip_name in vuln_sensor_list:
                    return True

                # 3) Check resonant frequency (should be within acoustic attack range)
                if (comp.resonant_frequency is not None) and (comp.resonant_frequency < 40000):
                    # 4) Check damping ratio (lower means sharper resonance, more vulnerable)
                    damping_ok = (comp.damping_ratio is not None and comp.damping_ratio < 0.1)
                    
                    # 5) Check if there's no acoustic isolation
                    if not comp.acoustic_isolation and damping_ok:
                        return True  # High risk

        return False
