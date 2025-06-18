from domaintools_misp.historic import dt_misp_module_historic

def handler(q=False):
    if not q:
        return q
    dtmm = dt_misp_module_historic()
    return dtmm.process_request(q)


def introspection():
    dtmm = dt_misp_module_historic()
    return dtmm.misp_attributes


def version():
    dtmm = dt_misp_module_historic()
    dtmm.module_info['config'] = dtmm.module_config
    return dtmm.module_info

