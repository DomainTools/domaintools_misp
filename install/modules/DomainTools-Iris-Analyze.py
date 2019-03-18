from domaintools_misp.iris_analyze import dt_misp_module_iris_analyze

def handler(q=False):
    if not q:
        return q
    dtmm = dt_misp_module_iris_analyze(True)
    dtmm.log.debug("DomainTools-Iris-Analyze.py")
    return dtmm.process_request(q)

def introspection():
    dtmm = dt_misp_module_iris_analyze()
    return dtmm.misp_attributes

def version():
    dtmm = dt_misp_module_iris_analyze()
    dtmm.module_info['config'] = dtmm.module_config
    return dtmm.module_info

