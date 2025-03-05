import os.path

from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling import SpoofingVulnerability
from saci.modeling.device import Device
from saci.modeling.device.sensor.accelerometer import Accelerometer, AccelerometerHardware
from saci.modeling.communication import UnauthenticatedCommunication, AuthenticatedCommunication, ExternalInput

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
