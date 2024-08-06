from saci.modeling import BaseVulnerability
from saci.modeling.device import  MicroController, VoltageGlitcher, Device

class VoltageInjectionVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            component = MicroController(),
            _input = VoltageGlitcher(),
            output = MicroController()
        )

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            if isinstance(comp, MicroController) and comp.chip_vendor == 'ARM' and comp.chip_series == 'Cortex' and comp.chip_name.startswith('M'):
                return True