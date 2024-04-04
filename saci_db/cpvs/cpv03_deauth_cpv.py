'''''
'''''
from saci.modeling import CPV, WiFiDeauthVuln
from saci.modeling.device import TelemetryHigh, ControllerHigh, Device
from saci.modeling.state import GlobalState

class WiFiDeauthDosCPV(CPV):
    def __init__(self):
        wifi_deauth_vuln = WiFiDeauthVuln()
        super().__init__(
            required_components=[
                wifi_deauth_vuln.component,
                TelemetryHigh,
                ControllerHigh,
            ],
            entry_component=TelemetryHigh(powered=True),
            vulnerabilities=[wifi_deauth_vuln]
        )

    def in_goal_state(self, state: GlobalState):
        # The goal state is now defined as a mission failure due to DoS on TelemetryHigh and ControllerHigh
        telemetry_dos = self.is_component_dos(state, TelemetryHigh)
        controller_dos = self.is_component_dos(state, ControllerHigh)

        # Mission failure occurs if both TelemetryHigh and ControllerHigh experience DoS
        return telemetry_dos and controller_dos

    def is_component_dos(self, state: GlobalState, component_type):
        # Check if a component of type component_type is experiencing a DoS
        for component in state.components:
            if isinstance(component, component_type):
                if component.powered and not component.connected:
                    return True
        return False

