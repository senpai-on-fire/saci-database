
from saci.modeling import CPV
from saci.modeling.device import Wifi, Motor

from saci_db.vulns.wifi_deauthentication_vuln import WiFiDeauthVuln
from saci_db.vulns.lack_wifi_auth_vuln import LackWifiAuthenticationVuln
from saci_db.vulns.lack_wifi_encryption_vuln import LackWifiEncryptionVuln

from saci.modeling.communication import ExternalInput

from saci.modeling.device import Controller

from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.state import GlobalState


# This is to model the attack in the CX-10W drone as described by the referenced paper,
class WiFiDeauthQuadDosCPV(CPV):
    NAME = "The WiFi Deauthentication Attack"

    def __init__(self):
        super().__init__(
            
            required_components=[
                Wifi(), # This is the entry component (Required)
                Controller(), # This is the controller hosting the firmware (Required)
                # PWMChannel(), # Removed since the PWMChannel is just a passthrough for the CPV (Not Required)
                # ESC(), # Removed since the ESC is just a passthrough for the CPV (Not Required)
                Motor(), # This is the exit component + Changed to Motor() for generalization (Required)
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
                "Operating mode": "Manual",
            },
            
            attack_requirements=[
                "ComputerWIFI card with monitor modeAircrack-ng software",
                "WIFI Credentials",
            ],
            
            attack_vectors=[
                BaseAttackVector(
                    name="Deauthentification Wifi Packets Injection",
                    signal=PacketAttackSignal(
                        src=ExternalInput(),
                        dst=Wifi(),
                    ),
                    required_access_level="Proximity",
                    #  aireplay-ng -0 0 -a [BSSID] [interface_name]
                    configuration={
                        "BSSID": "CPS's accsess point",
                        "interface_name": "wireless",
                        "other args": "-0 0 -a",
                    },
                )
            ],
            
            attack_impacts=[
                BaseAttackImpact(
                    category="Denial of Control",
                    description="The user can not stop the CPS",
                )
            ],
            
            exploit_steps=[
                "TA1 Exploit Steps",
                    "Reverse-engineer the CPS firmware to determine if the Wi-Fi implements security mechanisms such as Management Frame Protection (MFP).",
                    "Identify if the firmware has failsafe mechanisms to recover from deauthentication or if it enters a critical state.",
                    "Analyze the CPS control logic to assess how disconnection impacts movement and operation.",
                    "Create models for the following components: Ground control station, Wifi, CPS control logic, ESC logic and output, CPS actuators (e.g., motors) controlled by the ESC.",
                    "Report to TA2 any required physical parameters to simulate the CPS dynamics"
                "TA2 Exploit Steps",
                    "Implement a simulation of a Wi-Fi deauthentication attack on the CPS network.",
                    "Run the simulation to analyze how loss of communication translates to control failure in the CPS device.",
                    "Report the findings to TA3 to conduct the experiments on the physical CPS device",
                "TA3 Exploit Steps",
                    "Use imaging tools and other techniques to catalog all Wi-Fi-related hardware components on the CPS.",
                    "Identify physical interfaces that allow firmware extraction from the Wi-Fi module.",
                    "Identify the specific Wi-Fi module and extract the Wi-Fi SSID and password.",
                    "Connect the operator’s computer to the CPS’s Wi-Fi network.",
                    "Set the Wi-Fi card into monitor mode.",
                    "Find the BSSID and channel number for the 'FuelSource Wifi'.",
                    "Set the Wi-Fi card to monitor the correct channel.",
                    "On the operator’s computer, issue an HTTP GET request to the CPS device.",
                    "On the attacking computer, deauthenticate the control computer.",
                    "Observe that the operator’s computer is no longer connected and can no longer issue the stop command to the CPS.",
                    "Log Wi-Fi connection status and CPS behavior before, during, and after the attack.",
                    "Analyze the CPS’s physical response to communication disruption using telemetry and external tracking.",
            ],
            
            associated_files=[],
            reference_urls=[
                "https://docs.google.com/document/d/1DB4kHnwS-eE6Yy0G1dbc3fyc5Q4_A2Yz/edit",
                "https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8658279&tag=1",
            ],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
