from typing import List, Type

from saci.modeling import CPV
from saci.modeling.communication import ExternalInput

from saci_db.vulns.rf_interference_vuln import RFInterferenceVuln

from saci.modeling.attack.radio_attack_signal import RadioAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.device import GCS, Mavlink, Wifi, TelemetryHigh, SikRadio, ESC, PWMChannel, MultiCopterMotor
from saci.modeling.state import GlobalState

from saci_db.devices.ardupilot_quadcopter_device import ArduPilotQuadcopter


class RFJammingCPV(CPV):

    NAME = "The RF Jamming via External Signal Interference"

    def __init__(self):
        super().__init__(
            required_components=[
                GCS(),
                SikRadio(),   
                Mavlink(),  
                TelemetryHigh(),            
                ArduPilotQuadcopter(),
                PWMChannel(),  
                ESC(),
                MultiCopterMotor(),
            ],
            entry_component=Wifi(),        
            exit_component=MultiCopterMotor(), 

            vulnerabilities=[RFInterferenceVuln()],

            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any (>0)",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "Active",
                "Operating mode": "Manual or Semi-Autonomous",
            },

            attack_requirements=[
                "RF signal generator or jammer",
                "Knowledge of the UAV's communication frequency (e.g., 2.4 GHz or 5 GHz)",
                "Proximity to the UAV's operating area",
            ],

            attack_vectors=[
                BaseAttackVector(
                    name="RF Jamming Attack",
                    signal=RadioAttackSignal(
                        src=ExternalInput(),
                        dst=SikRadio(),
                    ),
                    required_access_level="Proximity",
                    configuration={
                        "attack_method": "Broadband RF jamming",
                        "frequency_range": "2.4 GHz or 5 GHz",
                        "target": "UAV communication channel",
                    },
                )
            ],

            attack_impacts=[
                BaseAttackImpact(
                    category="Denial of Service",
                    description="Disrupts telemetry and control signals, causing the UAV to lose communication with its controller."
                )
            ],

            exploit_steps=[
                "Identify the operating frequency of the UAV's communication system (e.g., using `airodump-ng` or a spectrum analyzer).",
                "Deploy an RF jammer to emit interference within the target frequency range.",
                "Observe the UAV's behavior to verify communication loss and activation of fail-safe mechanisms.",
            ],

            associated_files=[],
            reference_urls=[
                "https://media.defcon.org/DEF%20CON%2024/DEF%20CON%2024%20presentations/DEF%20CON%2024%20-%20Aaron-Luo-Drones-Hijacking-Multi-Dimensional-Attack-Vectors-And-Countermeasures-UPDATED.pdf"
            ]
        )

    def in_goal_state(self, state: GlobalState):
        return state.has_property("CommunicationLoss", True)
