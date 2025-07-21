from saci.modeling.device import Controller


class ArduPilotController(Controller):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
