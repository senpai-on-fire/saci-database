from saci.modeling.device import Controller


class ProprietyController(Controller):
    def __init__(self, has_external_input=True):
        super().__init__()
        self.has_external_input = has_external_input
