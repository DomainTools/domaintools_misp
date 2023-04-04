from domaintools_misp.iris_enrich import dt_misp_module_iris_enrich


def handler(q=False):
    if not q:
        return q
    dtmm = dt_misp_module_iris_enrich(True)
    dtmm.log.debug("DomainTools-Iris-Enrich.py")
    return dtmm.process_request(q)


def introspection():
    dtmm = dt_misp_module_iris_enrich()
    return dtmm.misp_attributes


def version():
    dtmm = dt_misp_module_iris_enrich()
    dtmm.module_info["config"] = dtmm.module_config
    return dtmm.module_info
