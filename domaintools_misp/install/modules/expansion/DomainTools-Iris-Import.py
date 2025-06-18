from domaintools_misp.iris_import import dt_misp_module_iris_import

def handler(q=False):
    dtmm = dt_misp_module_iris_import()
    return dtmm.handler(q)


def introspection():
    dtmm = dt_misp_module_iris_import()
    return dtmm.introspection()


def version():
    dtmm = dt_misp_module_iris_import()
    return dtmm.version()
