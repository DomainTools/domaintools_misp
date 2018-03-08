from domaintools_misp.analyze import dt_misp_module_analyze
from domaintools_misp.pivot import dt_misp_module_pivot
from domaintools_misp.historic import dt_misp_module_historic

__version__ = '0.1.5'

def register(mhandlers, loaded_modules):
    mhandlers.pop('domaintools', None)
    mhandlers.pop('type:domaintools', None)
    if 'domaintools' in loaded_modules:
        loaded_modules.remove('domaintools')

    mhandlers['DomainTools-Analyze'] = dt_misp_module_analyze()
    mhandlers['type:DomainTools-Analyze'] = 'expansion'
    loaded_modules.append('DomainTools-Analyze')

    mhandlers['DomainTools-Pivot'] = dt_misp_module_pivot()
    mhandlers['type:DomainTools-Pivot'] = 'expansion'
    loaded_modules.append('DomainTools-Pivot')

    mhandlers['DomainTools-Historic'] = dt_misp_module_historic()
    mhandlers['type:DomainTools-Historic'] = 'expansion'
    loaded_modules.append('DomainTools-Historic')
