import inspect

from saci_db.cpvs import CPVS


for cpv in CPVS:
    path = inspect.getmodule(cpv).__file__[:-2] + "lp"
    with open(path, "w") as f:
        cpv.write_asp(f)
