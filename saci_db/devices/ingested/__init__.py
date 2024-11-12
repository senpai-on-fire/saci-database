from pkgutil import iter_modules
from pathlib import Path
from importlib import import_module

from saci.modeling.device import Device

devices = {}

package_dir = Path(__file__).resolve().parent
for (_, module_name, _) in iter_modules([package_dir]):
    module = import_module(f"{__name__}.{module_name}")
    for attribute_name in dir(module):
        attr = getattr(module, attribute_name)
        if isinstance(attr, type) and issubclass(attr, Device):
            devices["ingested/" + attr.__name__] = attr()
