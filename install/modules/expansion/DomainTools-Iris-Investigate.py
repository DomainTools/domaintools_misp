from domaintools_misp.iris_investigate import dt_misp_module_iris_investigate


def handler(q=False):
    if not q:
        return q
    dtmm = dt_misp_module_iris_investigate(True)
    dtmm.log.debug("DomainTools-Iris-Investigate.py")
    return dtmm.process_request(q)


def introspection():
    dtmm = dt_misp_module_iris_investigate()
    return dtmm.misp_attributes


def version():
    dtmm = dt_misp_module_iris_investigate()
    dtmm.module_info["config"] = dtmm.module_config
    return dtmm.module_info
