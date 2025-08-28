from saci.modeling import CPV
from saci.modeling.device import Motor, ESC, Debug

from saci.modeling.communication import ExternalInput

from saci_db.vulns.lack_serial_auth_vuln import LackSerialAuthenticationVuln

from saci.modeling.attack.serial_attack_signal import SerialAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.state import GlobalState


class SerialESCBootloaderCPV(CPV):
    NAME = "The ESC Bootloader via Serial Interface"

    def __init__(self):
        super().__init__(
            required_components=[
                Debug(),  # This is the entry component (Required)
                ESC(),  # This is a required vulnerable component (Required)
                Motor(),  # This is the exit component (Required)
            ],
            entry_component=Debug(),
            exit_component=Motor(),
            vulnerabilities=[LackSerialAuthenticationVuln()],
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any",
                "Environment": "Any",
                "Software state": "On",
                "Operator Supervision": "Any",
                "OperatingMode": "Manual or Mission",
            },
            attack_requirements=[
                "physical access",
                "Debugging/programming hardware",
                "Software tools for accessing and programming STM32 microprocessors.",
                "Knowledge of STM32 boot-loader mode",
                "knowledge of programming protocols.",
            ],
            attack_vectors=[
                BaseAttackVector(
                    name="Debug Commands Injection",
                    signal=SerialAttackSignal(src=ExternalInput(), dst=Debug()),
                    required_access_level="Physical",
                )
            ],
            attack_impacts=[BaseAttackImpact(category="Loss of control", description="ESC will not start motor")],
            exploit_steps=[
                "TA1 Exploit Steps",
                "Reverse-engineer the ESC firmware to determine if its debug interface is vulnerable to command injection.",
                "Identify if the ESC firmware has failsafe mechanisms to recover from malicious commands over the debug interface.",
                "Analyze the ESC control logic how malicious debug commands can stop the motor.",
                "Create models for the following components: ESC with debug interface, Battery, ESC logic and output, Actuators (e.g., motors) controlled by the ESC.",
                "Report to TA2 any required environmental factors (e.g., temperature) to simulate the battery state."
                "TA2 Exploit Steps",
                "Create an automata to simulate a malicious debug command injection on the BMS.",
                "Use a fuzzing tool to fuzz the functions and generate a malicious debug commands that directly stop the motor operation.",
                "Report the findings to TA3 to conduct the experiments on the physical CPS device",
                "TA3 Exploit Steps",
                "Use optical imaging tools to catalog all of the components on the CPS.",
                "Identify which components contained memory that might contain ESC firmware.",
                "Extract the ESC firmware from the ESC memory component.",
                "Connect to the ESC via a USB-TTL serial adapter using a terminal emulator with a baud rate of 38400.",
                "Arm the ESC and start the motor.",
                "Use the microprocessor programmer to connect to the STM32.",
                "Follow the procedure to write the HII-GSP1AESC01NR017-CPV003_FF.hex file to the STM32.",
                "Use the microprocessor programmer to reset the STM32.",
                "Reconnect to the USB-TTL serial adapter using the terminal emulator.",
                "The terminal emulator will likely not connect and the motor does not begin to spin.",
            ],
            associated_files=[],
            reference_urls=[
                "https://github.com/senpai-on-fire/Greensight1A-esc-CPVs/blob/main/CPV003/HII-GSP1AESC01NR017-CPV003-20241002.docx"
            ],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
