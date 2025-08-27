from typing import List
from saci.modeling import CPV

from saci.modeling.device import (
    AirspeedSensor,
    Serial,
    PWMChannel,
    ESC,
    FixedWingMotor,
    Motor,
    Controller,
)  # Need to confirm model for AirspeedSensor & FixedWingMotor device
from saci_db.devices.px4_fixedwing_device import PX4FixedWingController

from saci_db.vulns.airspeed_spoofing_vuln import AirspeedSpoofingVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln

from saci.modeling.communication import ExternalInput
from saci.modeling.state import GlobalState

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.acoustic_attack_signal import AcousticAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact


class AcousticSpoofingAirspeedCPV(CPV):
    NAME = "The Acoustic Spoofing Attack on Airspeed Sensors"

    def __init__(self):
        super().__init__(
            
            required_components=[
                AirspeedSensor(), # This is the entry component (Required)
                # Serial(), # Removed considering that the AirspeedSensor is inherently connected to the Controller via Serial (Not Required)
                Controller(), # This is the controller hosting the firmware (Required)
                # PWMChannel(), # Removed since the PWMChannel is just a passthrough for the CPV (Not Required)
                # ESC(), # Removed since the ESC is just a passthrough for the CPV (Not Required)
                Motor(), # This is the exit component + Changed to Motor() for generalization (Required)
            ],
            
            entry_component=AirspeedSensor(),
            exit_component=Motor(),
            
            vulnerabilities=[AirspeedSpoofingVuln(), ControllerIntegrityVuln()],
            
            goals=[],
            
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "None",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "None",
                "OperatingMode": "Mission",
            },
            
            attack_requirements=["Speaker or Ultrasonic Sound Source"],
            
            attack_vectors=[
                BaseAttackVector(
                    name="Acoustic Spoofing Signal Injection",
                    signal=AcousticAttackSignal(
                        src=ExternalInput(),
                        dst=AirspeedSensor(),
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
                    description="CPS is unable to maintain commanded altitude.",
                )
            ],
            
            exploit_steps=[
                "TA1 Exploit Steps",
                    "Reverse-engineer the CPS firmware to determine if sensor fusion or filtering mechanisms exist for airspeed data.",
                    "Analyze the position control logic to assess how fluctuations in airspeed readings propagate to motor actuation.",
                "TA2 Exploit Steps",
                    "Implement a simulation of airspeed sensor response to acoustic interference.",
                    "Inject synthetic acoustic noise into the control loop and measure controller response.",
                    "Simulate how abnormal airspeed readings propagate through the CPS system.",
                    "Report the findings to TA3 to conduct the experiments on the physical CPS device",
                "TA3 Exploit Steps",
                    "Use imaging tools and other techniques to catalog all components on the CPS.",
                    "Identify if an airspeed sensor is present.",
                    "Mount the airspeed sensor (or CPS) in a vibration-free environment and measure output when exposed to an acoustic frequency sweep (e.g., 20Hz to 30kHz).",
                    "Observe airspeed sensor output for spikes and increased standard deviation to detect resonance-induced errors.",
                    "Identify the resonant frequency at the point of maximum deviation from the true value.",
                    "Position an ultrasonic transducer/speaker near the CPS and emit the resonant frequency.",
                    "Log airspeed sensor data before, during, and after the attack.",
                    "Analyze the CPS's physical response using external tracking and onboard telemetry.",
            ],
            
            associated_files=[],
            reference_urls=[],
        )

    def in_goal_state(self, state: GlobalState):
        pass
