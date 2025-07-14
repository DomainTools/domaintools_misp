from domaintools_misp.iris_detect import dt_misp_module_iris_detect


def handler(q=False):
    if not q:
        return q

    dtmm = dt_misp_module_iris_detect()
    return dtmm.process_request(q)


def introspection():
    dtmm = dt_misp_module_iris_detect()
    return dtmm.introspection()


def version():
    dtmm = dt_misp_module_iris_detect()
    return dtmm.version()
