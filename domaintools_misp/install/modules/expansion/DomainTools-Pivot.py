from domaintools_misp.pivot import dt_misp_module_pivot

def handler(q=False):
    if not q:
        return q
    dtmm = dt_misp_module_pivot()
    return dtmm.process_request(q)


def introspection():
    dtmm = dt_misp_module_pivot()
    return dtmm.misp_attributes


def version():
    dtmm = dt_misp_module_pivot()
    dtmm.module_info['config'] = dtmm.module_config
    return dtmm.module_info
