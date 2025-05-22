import os.path

from clorm import Predicate

from saci.modeling import SpoofingVulnerability

from saci.modeling.device import Device
from saci.modeling.device.sensor import AirspeedSensor

from saci.modeling.communication import AuthenticatedCommunication, ExternalInput
from saci.modeling.attack import BaseAttackVector, AcousticAttackSignal, BaseCompEffect


class AirspeedSpoofingPred(Predicate):
    pass


class AirspeedSpoofingVuln(SpoofingVulnerability):
    def __init__(self):
        super().__init__(
            component=AirspeedSensor(),
            _input=AuthenticatedCommunication(src=ExternalInput()),
            output=AuthenticatedCommunication(),
            attack_ASP=AirspeedSpoofingPred,
            #
            # rulefile=os.path.join(
            #    os.path.dirname(os.path.realpath(__file__)), "airspeed_spoofing.lp"
            # ),
            associated_cwe=[
                "CWE-346: Origin Validation Error",
                "CWE-20: Improper Input Validation",
                "CWE-693: Protection Mechanism Failure",
            ],
            attack_vectors_exploits=[
                {
                    "attack_vector": [
                        BaseAttackVector(
                            name="Acoustic Pressure Manipulation",
                            signal=AcousticAttackSignal(
                                src=ExternalInput(),
                                dst=AirspeedSensor(),
                                modality="audio",
                            ),
                            required_access_level="close proximity or physical",
                            configuration={
                                "attack_method": "Emit acoustic interference targeting the airspeed sensor",
                                "equipment": "Speaker or Ultrasonic Sound Source",
                                "target_frequency": "Resonant Frequency",
                            },
                        )
                    ],
                    "related_cpv": [
                        "AcousticSpoofingAirspeedCPV",
                    ],
                    "comp_attack_effect": [
                        BaseCompEffect(
                            category="Integrity",
                            description="Manipulated dynamic‑pressure readings lead to incorrect velocity estimation and potential loss of flight‑path control.",
                        )
                    ],
                    "exploit_steps": [
                        "Reverse-engineer the CPS firmware to determine if sensor fusion or filtering mechanisms exist for airspeed data.",
                        "Analyze the position control logic to assess how fluctuations in airspeed readings propagate to motor actuation.",
                        "Implement a simulation of airspeed sensor response to acoustic interference.",
                        "Inject synthetic acoustic noise into the control loop and measure controller response.",
                        "Simulate how abnormal airspeed readings propagate through the CPS system.",
                        "Report the findings to TA3 to conduct the experiments on the physical CPS device",
                        "Use imaging tools and other techniques to catalog all components on the CPS.",
                        "Identify if an airspeed sensor is present.",
                        "Mount the airspeed sensor (or CPS) in a vibration-free environment and measure output when exposed to an acoustic frequency sweep (e.g., 20Hz to 30kHz).",
                        "Observe airspeed sensor output for spikes and increased standard deviation to detect resonance-induced errors.",
                        "Identify the resonant frequency at the point of maximum deviation from the true value.",
                        "Position an ultrasonic transducer/speaker near the CPS and emit the resonant frequency.",
                        "Log airspeed sensor data before, during, and after the attack.",
                        "Analyze the CPS's physical response using external tracking and onboard telemetry.",
                    ],
                    "reference_urls": [
                        # No peer‑reviewed publications as of 2025‑05‑21
                    ],
                }
            ],
        )

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            if isinstance(comp, AirspeedSensor):
                return True
        return False
