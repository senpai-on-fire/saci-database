from saci.modeling import CPV
from saci.modeling.device import (
    Controller,
    Serial,
)
from saci.modeling.device.motor import Motor
from saci.modeling.state import GlobalState

from saci_db.vulns.lack_serial_auth_vuln import LackSerialAuthenticationVuln

from saci.modeling.communication import ExternalInput

from saci.modeling.attack.serial_attack_signal import SerialAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact


class SerialThrottleCPV(CPV):
    NAME = "The Throttle the Rover via Serial Interface"

    def __init__(self):
        super().__init__(
            required_components=[
                Serial(),  # This is the entry component (Required)
                Controller(),  # This is the controller hosting the firmware (Required)
                # CANTransceiver(), # Removed for generalization since it's not required and too specific (Not required)
                # CANTransceiver(), # Removed for generalization since it's not required and too specific (Not required)
                # CANBus(), # Removed for generalization since it's not required and too specific (Not required)
                # CANShield(), # Removed for generalization since it's not required and too specific (Not required)
                # PWMChannel(), # Removed since the PWMChannel is just a passthrough for the CPV (Not Required)
                # ESC(), # Removed since the ESC is just a passthrough for the CPV (Not Required)
                Motor(),  # This is the exit component + Changed to Motor() for generalization (Required)
            ],
            entry_component=Serial(),
            exit_component=Motor(),
            vulnerabilities=[LackSerialAuthenticationVuln()],
            goals=[],
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "Moving",
                "OperatingMode": "Manual or Mission",
            },
            attack_vectors=[
                BaseAttackVector(
                    name="Serial DSHOT Command Injection",
                    signal=SerialAttackSignal(
                        src=ExternalInput(), dst=Serial(), data="any"
                    ),  # data excludes values 55, 66, 77
                    required_access_level="Physical",
                )
            ],
            attack_requirements=["Computer", "USB-C cable"],
            attack_impacts=[
                BaseAttackImpact(
                    category="Manipulation of Control",
                    description="The serial commands cause CPS device to start moving/driving",
                )
            ],
            exploit_steps=[
                "TA1 Exploit Steps",
                "Reverse-engineer the CPS firmware to determine if the serial interface is vulnerable to command injection.",
                "Identify if the firmware has failsafe mechanisms to recover from malicious serial commands.",
                "Analyze the CPS control logic to assess how malicious serial commands can manipulate the CPS movements before the start of the mission.",
                "Create models for the following components: CPS control logic with serial interface, ESC logic and output, CPS actuators (e.g., motors) controlled by the ESC.",
                "Report to TA2 any required physical parameters to simulate the CPS dynamicsTA2 Exploit Steps",
                "Create an automata to simulate a malicious serial command injection on the CPS dynamics.",
                "Use a fuzzing tool to fuzz the functions and generate a malicious serial commands that manipulate the CPS throttle.",
                "Report the findings to TA3 to conduct the experiments on the physical CPS device",
                "TA3 Exploit Steps",
                "Open a terminal emulator and connect to the serial device exposed by the CPS device. You may need root access.",
                "When the CPS is Idle, enter any number between 48-2047 (except 55, 66, & 77) into the terminal",
            ],
            associated_files=[],
            reference_urls=["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV0011"],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
