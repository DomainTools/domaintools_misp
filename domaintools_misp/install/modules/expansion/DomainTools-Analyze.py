from domaintools_misp.analyze import dt_misp_module_analyze

def handler(q=False):
    if not q:
        return q
    dtmm = dt_misp_module_analyze(True)
    return dtmm.process_request(q)

def introspection():
    dtmm = dt_misp_module_analyze()
    return dtmm.misp_attributes

def version():
    dtmm = dt_misp_module_analyze()
    dtmm.module_info['config'] = dtmm.module_config
    return dtmm.module_info

