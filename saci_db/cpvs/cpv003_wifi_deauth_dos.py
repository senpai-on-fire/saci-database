from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (
    Controller,
    Wifi,
    Controller,
    Motor,
    WebServer,
    PWMChannel,
    ESC,
    CANBus,
    CANTransceiver,
    CANShield,
)

from saci_db.vulns.wifi_deauthentication_vuln import WiFiDeauthVuln
from saci_db.vulns.lack_wifi_auth_vuln import LackWifiAuthenticationVuln
from saci_db.vulns.lack_wifi_encryption_vuln import LackWifiEncryptionVuln

from saci.modeling.communication import ExternalInput
from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.state import GlobalState


class WiFiDeauthDosCPV(CPV):
    NAME = "The WiFi Deauthentication Attack"

    def __init__(self):
        super().__init__(
            required_components=[
                Wifi(),
                WebServer(),
                Controller(),
                CANTransceiver(),
                CANBus(),
                CANShield(),
                Controller(),
                PWMChannel(),
                ESC(),
                Motor(),
            ],
            entry_component=Wifi(),
            exit_component=Motor(),
            vulnerabilities=[
                WiFiDeauthVuln(),
                LackWifiAuthenticationVuln(),
                LackWifiEncryptionVuln(),
            ],
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any (>0)",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "Moving",
                "OperatingMode": "Manual",
            },
            attack_requirements=[
                "ComputerWIFI card with monitor modeAircrack-ng software",
                "WIFI Credentials",
            ],
            attack_vectors=[
                BaseAttackVector(
                    name="Deauthentification Wifi Packets Injection",
                    signal=PacketAttackSignal(src=ExternalInput(), dst=Wifi()),
                    required_access_level="Proximity",
                    #  aireplay-ng -0 0 -a [BSSID] [interface_name]
                    configuration={
                        "BSSID": "FuelSource Wifi",
                        "interface_name": "wireless",
                        "other args": "-0 0 -a",
                    },
                )
            ],
            attack_impacts=[
                BaseAttackImpact(
                    category="Denial of control",
                    description="The user can not stop the CPS",
                )
            ],
            exploit_steps=[
                "TA1 Exploit Steps",
                "Reverse-engineer the CPS firmware to determine if the Wi-Fi implements security mechanisms such as Management Frame Protection (MFP).",
                "Identify if the firmware has failsafe mechanisms to recover from deauthentication or if it enters a critical state.",
                "Analyze the CPS control logic to assess how disconnection impacts movement and operation.",
                "Create models for the following components: Wifi, Webserver, CPS control logic, ESC logic and output, CPS actuators (e.g., motors) controlled by the ESC.",
                "Report to TA2 any required physical parameters to simulate the CPS dynamics"
                "TA2 Exploit Steps",
                "Implement a simulation of a Wi-Fi deauthentication attack on the CPS network.",
                "Run the simulation to analyze how loss of communication translates to control failure in the CPS device.",
                "Report the findings to TA3 to conduct the experiments on the physical CPS device",
                "TA3 Exploit Steps",
                "Use imaging tools and other techniques to catalog all Wi-Fi-related hardware components on the CPS.",
                "Identify physical interfaces that allow firmware extraction from the Wi-Fi module.",
                "Identify the specific Wi-Fi module and extract the Wi-Fi SSID and password.",
                "Connect the operator’s computer to the rover’s Wi-Fi network.",
                "Set the Wi-Fi card into monitor mode.",
                "Find the BSSID and channel number for the 'FuelSource Wifi'.",
                "Set the Wi-Fi card to monitor the correct channel.",
                "On the operator’s computer, issue an HTTP GET request to `http://192.168.4.1/Demo`.",
                "Ensure the rover begins to drive.",
                "On the attacking computer, deauthenticate the control computer.",
                "Observe that the operator’s computer is no longer connected and can no longer issue the stop command to the rover.",
                "Log Wi-Fi connection status and CPS behavior before, during, and after the attack.",
                "Analyze the CPS’s physical response to communication disruption using telemetry and external tracking.",
            ],
            associated_files=[],
            reference_urls=[
                "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/blob/main/CPV001"
            ],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
