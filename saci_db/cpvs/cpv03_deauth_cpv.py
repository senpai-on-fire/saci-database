'''''
'''''
from saci.modeling import CPV, WiFiDeauthVuln
from saci.modeling.device import TelemetryHigh, ControllerHigh, Device
from saci.modeling.state import GlobalState

# Define the CPV for the WiFi De-authentication Attack
class WiFiDeauthCPV(CPV):
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
    # goal state as the controller being in an emergency state
    for component in state.components:
        if isinstance(component, TelemetryHigh) and component.protocol_name == "wifi":
            # Check if the WiFi component is in a disconnected state due to the de-authentication attack
            if component.powered and not component.connected:
                # check the state of the controller
                controller = next((comp for comp in state.components if isinstance(comp, ControllerHigh)), None)
                if controller:
                    # Assuming there's an attribute 'emergency_state' that indicates the controller is in an emergency mode
                    return controller.emergency_state
    return False

