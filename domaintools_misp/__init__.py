from domaintools_misp.analyze import dt_misp_module_analyze
from domaintools_misp.iris_detect import dt_misp_module_iris_detect
from domaintools_misp.iris_enrich import dt_misp_module_iris_enrich
from domaintools_misp.iris_import import dt_misp_module_iris_import
from domaintools_misp.iris_investigate import dt_misp_module_iris_investigate
from domaintools_misp.iris_pivot import dt_misp_module_iris_pivot
from domaintools_misp.pivot import dt_misp_module_pivot
from domaintools_misp.historic import dt_misp_module_historic
from domaintools_misp._version import current

__version__ = current


def register(mhandlers, loaded_modules):
    mhandlers.pop("domaintools", None)
    mhandlers.pop("type:domaintools", None)
    if "domaintools" in loaded_modules:
        loaded_modules.remove("domaintools")

    mhandlers["DomainTools-Analyze"] = dt_misp_module_analyze()
    mhandlers["type:DomainTools-Analyze"] = "expansion"
    loaded_modules.append("DomainTools-Analyze")

    mhandlers["DomainTools-Iris-Investigate"] = dt_misp_module_iris_investigate()
    mhandlers["type:DomainTools-Iris-Investigate"] = "expansion"
    loaded_modules.append("DomainTools-Iris-Investigate")

    mhandlers["DomainTools-Pivot"] = dt_misp_module_pivot()
    mhandlers["type:DomainTools-Pivot"] = "expansion"
    loaded_modules.append("DomainTools-Pivot")

    mhandlers["DomainTools-Iris-Pivot"] = dt_misp_module_iris_pivot()
    mhandlers["type:DomainTools-Iris-Pivot"] = "expansion"
    loaded_modules.append("DomainTools-Iris-Pivot")

    mhandlers["DomainTools-Historic"] = dt_misp_module_historic()
    mhandlers["type:DomainTools-Historic"] = "expansion"
    loaded_modules.append("DomainTools-Historic")

    mhandlers["DomainTools-Iris-Import"] = dt_misp_module_iris_import()
    mhandlers["type:DomainTools-Iris-Import"] = "import"
    loaded_modules.append("DomainTools-Iris-Import")

    mhandlers["DomainTools-Iris-Enrich"] = dt_misp_module_iris_enrich()
    mhandlers["type:DomainTools-Iris-Enrich"] = "expansion"
    loaded_modules.append("DomainTools-Iris-Enrich")

    mhandlers["DomainTools-Iris-Detect"] = dt_misp_module_iris_detect()
    mhandlers["type:DomainTools-Iris-Detect"] = "import"
    loaded_modules.append("DomainTools-Iris-Detect")
