import json
import tldextract
import time
import re
import hashlib
import logging
import sys
from dateutil import parser
from domaintools import API
from domaintools.exceptions import (BadRequestException, InternalServerErrorException, NotAuthorizedException,
                                    NotFoundException, ServiceException, ServiceUnavailableException)

class dt_module_helpers():
    def __init__(self, plugin):
        self.plugin = plugin

    def append_unique_payload(self, payload):
        m = hashlib.md5()
        for k in payload['values']:
            if k == '':
                continue

            if payload['values'][k] == '':
                if len(payload['values']) == 1:
                    return
                continue

            m.update('{0}'.format(k).encode('utf-8'))
            m.update('{0}'.format(payload['values'][k]).encode('utf-8'))

        item = m.hexdigest()
        if item not in self.plugin.unique:
            self.plugin.unique[item] = True
            self.plugin.payload.append(payload)

    def append_unique_value(self, a_list, a_value):
        a_list.append(a_value)
        a_set = set(a_list)
        return list(a_set)

    def module_has_type(self, type):
        for t in self.plugin.module_info['module-type']:
            if t == type:
                return True
        return False

    def format_age(self, age):
        if age < 60:
            return '{age} seconds'.format(age=age)
        elif age < (60 * 60):
            return '{age} minutes'.format(age=round(age / 60, 1))
        elif age < (60 * 60 * 24):
            return '{age} hours'.format(age=round(age / (60 * 60), 1))
        elif age < (60 * 60 * 24 * 7):
            return '{age} days'.format(age=round(age / (60 * 60 * 24), 1))
        elif age < (60 * 60 * 24 * 30):
            return '{age} weeks'.format(age=round(age / (60 * 60 * 24 * 7), 1))
        elif age < (60 * 60 * 24 * 365):
            return '{age} months'.format(age=round(age / (60 * 60 * 24 * 30), 1))
        else:
            return '{age} years'.format(age=round(age / (60 * 60 * 24 * 365), 1))

    def calculate_age(self, born):
        return self.format_age(time.time() - time.mktime(parser.parse(born).timetuple()))

    def safe_path(self, src, path):
        self.safe_path_result = None
        ptr = src
        for p in path:
            if p in ptr:
                ptr = ptr[p]
            else:
                return False
        self.safe_path_result = ptr
        return True

    def safe_get(self, src, key):
        self.safe_get_result = src.get(key, None)
        return self.safe_get_result is not None and self.safe_get_result != ''

    def multiplex_atrb(self, src, keys, label):
        self.multiplex_atrb_result = ''
        values = []
        for key in keys:
            if self.safe_path(src,
                                     ['contacts', 'admin', key]):
                if type(self.safe_path_result) is list:
                    for item in self.safe_path_result:
                        if item != '' and item not in values:
                            self.append_unique_value(values, item)
                else:
                    if self.safe_path_result != '':
                        self.append_unique_value(values, self.safe_path_result)
            if self.safe_path(src,
                                     ['contacts', 'billing',
                                      key]):
                if type(self.safe_path_result) is list:
                    for item in self.safe_path_result:
                        if item != '' and item not in values:
                            self.append_unique_value(values, item)
                else:
                    if self.safe_path_result != '':
                        self.append_unique_value(values, self.safe_path_result)
            if self.safe_path(src,
                                     ['contacts', 'registrant',
                                      key]):
                if type(self.safe_path_result) is list:
                    for item in self.safe_path_result:
                        if item != '' and item not in values:
                            self.append_unique_value(values, item)
                else:
                    if self.safe_path_result != '':
                        self.append_unique_value(values, self.safe_path_result)
            if self.safe_path(src,
                                     ['contacts', 'tech',
                                      key]):
                if type(self.safe_path_result) is list:
                    for item in self.safe_path_result:
                        if item != '':
                            self.append_unique_value(values, item)
                else:
                    if self.safe_path_result != '':
                        self.append_unique_value(values, self.safe_path_result)
        for item in values:
            self.multiplex_atrb_result = {'types': ['{key}'.format(key=label)],
                                                 'values': {label: item},
                                                 'comment': '{0} from DomainTools'.format(label),
                                                 'tags': ['DomainTools', 'whois', label]}

    def simple_parse(self, _what, _from_where, _types=['text'], _comment='{0} from DomainTools',
                            _tags=['DomainTools', 'whois'], _label='{0}', _categories=['External analysis'],
                            _parent=None):
        if _parent is not None:
            _comment = '{0} -> {1}'.format(_parent, _comment)
            _label = '{0} -> {1}'.format(_parent, _label)
        if type(_from_where) is dict:
            if _what == '*':
                for dict_key in _from_where:
                    _tags_local = _tags[:]
                    self.simple_parse(dict_key, _from_where, _types,
                                             _comment,
                                             self.append_unique_value(_tags_local, _what.replace('_', ' ')),
                                             _label, _categories)
            elif self.safe_get(_from_where, _what):
                if type(self.safe_get_result) is dict:
                    for dict_key in self.safe_get_result:
                        _tags_local = _tags[:]
                        self.simple_parse(dict_key, self.safe_get_result, _types,
                                                 _comment.format(_what.replace('_', ' ') + ' -> {0}'),
                                                 self.append_unique_value(_tags_local, _what.replace('_', ' ')),
                                                 _label.format(_what.replace('_', ' ') + ' -> {0}'), _categories)
                elif type(self.safe_get_result) is list:
                    for item in self.safe_get_result:
                        _tags_local = _tags[:]
                        self.simple_parse('*', item, _types,
                                                 _comment.format(_what.replace('_', ' ') + ' -> {0}'),
                                                 self.append_unique_value(_tags_local, _what.replace('_', ' ')),
                                                 _label.format(_what.replace('_', ' ') + ' -> {0}'), _categories)

                        # self.append_unique_payload({'types': _types, 'values': {_label.format(_what.replace('_',' ')): item}, 'comment': _comment.format(_what.replace('_',' ')), 'tags': self.append_unique_value(_tags_local,_what.replace('_',' ')), 'categories': _categories})
                else:
                    self.append_unique_payload({'types': _types, 'values': {
                        _label.format(_what.replace('_', ' ')): self.safe_get_result},
                                                       'comment': _comment.format(_what.replace('_', ' ')),
                                                       'tags': _tags, 'categories': _categories})
        elif type(_from_where) is list:
            for item in _from_where:
                _tags_local = _tags[:]
                self.simple_parse(_what, item, _types,
                                         _comment.format(_what.replace('_', ' ') + ' -> {0}'),
                                         self.append_unique_value(_tags_local, _what.replace('_', ' ')),
                                         _label.format(_what.replace('_', ' ') + ' -> {0}'), _categories)
        else:
            self.append_unique_payload(
                {'types': _types, 'values': {_label.format(_what.replace('_', ' ')): _from_where},
                 'comment': _comment.format(_what.replace('_', ' ')), 'tags': _tags, 'categories': _categories})


class dt_misp_module_base:
    def __init__(self):
        self.misp_attributes = {
            'input': ['domain', 'hostname', 'url', 'uri', 'email-src', 'email-dst', 'target-email',
                      'whois-registrant-email',
                      'whois-registrant-name', 'whois-registrant-phone', 'ip-src', 'ip-dst', 'whois-creation-date',
                      'text'],
            'output': ['whois-registrant-email', 'whois-registrant-phone', 'whois-registrant-name',
                       'whois-registrar', 'whois-creation-date', 'comment', 'domain', 'ip-src', 'ip-dst', 'text']
        }

        self.module_config = ['username', 'api_key', 'results_limit']
        self.results_limit = 100
        self.historic_enabled = False
        self.debug = False
        self.payload = list()
        self.unique = dict()
        self.errors = {'error': 'An unknown error has occurred'}
        self.helper = dt_module_helpers(self)
        self.log = logging.getLogger('DomainTools')
        self.log.setLevel(logging.DEBUG)
        self.ch = logging.StreamHandler(sys.stdout)
        self.ch.setLevel(logging.DEBUG)
        self.formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.ch.setFormatter(self.formatter)
        self.log.addHandler(self.ch)

    def check_config(self, request):
        """Check the incoming request for valid info."""
        self.config = request.get('config', None)
        if self.config is None:
            self.errors['error'] = "Configuration is missing from the request."
            return False

        if self.config.get('username', None) is None:
            self.errors['error'] = "DomainTools API username is not configured."
            return False

        if self.config.get('api_key', None) is None:
            self.errors['error'] = "DomainTools API key is not configured."
            return False

        if self.helper.module_has_type('expansion') and self.config.get('results_limit', None) is None:
            self.config['results_limit'] = self.results_limit

        self.api = dt_api_adapter_misp(self)
        self.svc_map = {
            'text': [self.api.parsed_whois, self.api.domain_profile, self.api.reputation, self.api.hosting_history,
                     self.api.whois_history, self.api.risk],
            'domain': [self.api.parsed_whois, self.api.domain_profile, self.api.reputation, self.api.hosting_history,
                       self.api.whois_history, self.api.risk],
            'hostname': [self.api.parsed_whois, self.api.domain_profile, self.api.reputation, self.api.hosting_history,
                         self.api.whois_history, self.api.risk],
            'url': [self.api.parsed_whois, self.api.domain_profile, self.api.reputation, self.api.hosting_history,
                    self.api.whois_history, self.api.risk],
            'uri': [self.api.parsed_whois, self.api.domain_profile, self.api.reputation, self.api.hosting_history,
                    self.api.whois_history, self.api.risk],
            'email-src': [self.api.reverse_whois],
            'email-dst': [self.api.reverse_whois],
            'target-email': [self.api.reverse_whois],
            'whois-registrant-email': [self.api.reverse_whois],
            'whois-registrant-name': [self.api.reverse_whois],
            'whois-registrant-phone': [self.api.reverse_whois],
            'ip-src': [self.api.host_domains, self.api.parsed_whois, self.api.hosting_history],
            'ip-dst': [self.api.host_domains, self.api.parsed_whois, self.api.hosting_history],
            'whois-creation-date': [self.api.reverse_whois]
        }

        return True

    def process_request(self, request_raw):
        try:
            self.__init__()
            if self.debug:
                self.log.debug("process_request: {0}".format(request_raw))
            request = json.loads(request_raw)
            proceed = self.check_config(request)
            if proceed:
                for type in self.misp_attributes['input']:
                    if type in request:
                        for svc in self.svc_map[type]:
                            try:
                                svc(request[type])
                            except BadRequestException as e:
                                self.log.debug("API returned a Bad Request response: {0}".format(request[type]))
                                pass
                            except NotAuthorizedException as e:
                                self.log.debug("API returned a Not Authorized response: {0}".format(request[type]))
                                pass
                            except NotFoundException as e:
                                self.log.debug("API returned a Not Found response: {0}".format(request[type]))
                                pass
                            except InternalServerErrorException as e:
                                self.log.debug("API returned a Internal Server Error response: {0}".format(request[type]))
                                pass
                            except ServiceUnavailableException as e:
                                self.log.debug("API returned a Service Unavailable response: {0}".format(request[type]))
                                pass
                            except ServiceException as e:
                                self.log.debug("API returned a Service Error response: {0}".format(request[type]))
                                pass
                        break  # can there realistically be more than one type in a request?
                return {'results': self.payload}
        except NotFoundException as e:
            self.errors = {'results': 'No information found'}

        return self.errors


class dt_api_adapter_misp():
    def __init__(self, plugin):
        self.plugin = plugin
        self.helper = plugin.helper
        self.svc_enabled = dict()
        self.api = API(username=plugin.config.get('username'), key=plugin.config.get('api_key'), app_partner='MISP',
                       app_name=plugin.module['name'], app_version=plugin.module_info['version'])
        self.account_information = self.api.account_information().data()
        for svc in self.account_information['response']['products']:
            if svc['per_month_limit'] is not None:
                self.svc_enabled[svc['id']] = int(svc['per_month_limit']) - int(svc['usage']['month'])

            else:
                self.svc_enabled[svc['id']] = True

    def parsed_whois(self, query):
        if 'parsed-whois' not in self.svc_enabled or self.svc_enabled['parsed-whois'] <= 0:
            if self.plugin.debug:
                self.plugin.log.debug("parsed-whois: service disabled or over monthly limit")

        if self.plugin.module['name'] == 'DomainTools-Historic':
            return True

        tldex = tldextract.extract(query.replace('\\/', '/'))
        q = '.'.join(tldex[1:])
        if q == '':
            return True
        method = self.api.parsed_whois(q)
        results = method.data()
        results = results['response']
        if method._status != 200:
            return True
        results = results.get('parsed_whois')
        if results.get('source'):
            if self.helper.module_has_type('expansion'):
                if self.helper.safe_get(results, 'contacts'):
                    for contact in self.helper.safe_get_result:
                        self.helper.simple_parse('abuse_mailbox', contact, ['email-src', 'email-dst'])
                        self.helper.simple_parse('address', contact)
                        self.helper.simple_parse('changed_by', contact)
                        self.helper.simple_parse('descr', contact)
                        self.helper.simple_parse('fax', contact, ['whois-registrant-phone'])
                        self.helper.simple_parse('notify_email', contact, ['whois-registrant-email'])
                        self.helper.simple_parse('phone', contact, ['whois-registrant-phone'])
                        self.helper.simple_parse('remarks', contact)
                        self.helper.simple_parse('contact_keys', contact)
                        self.helper.simple_parse('mnt_keys', contact)
                        self.helper.simple_parse('other', contact)
                        self.helper.simple_parse('country', contact)
                        self.helper.simple_parse('created_date', contact, ['whois-creation-date'])
                        self.helper.simple_parse('id', contact)
                        self.helper.simple_parse('name', contact, ['whois-registrant-name'])
                        self.helper.simple_parse('ref', contact, ['url', 'uri'])
                        self.helper.simple_parse('source', contact)
                        self.helper.simple_parse('type', contact)
                        self.helper.simple_parse('updated_date', contact)
                if self.helper.safe_get(results, 'networks'):
                    for network in self.helper.safe_get_result:
                        self.helper.simple_parse('asn', network)
                        self.helper.simple_parse('changed_by', network)
                        self.helper.simple_parse('contact_keys', network)
                        self.helper.simple_parse('country', network)
                        self.helper.simple_parse('created_date', network, ['whois-creation-date'])
                        self.helper.simple_parse('customer', network)
                        self.helper.simple_parse('descr', network)
                        self.helper.simple_parse('id', network)
                        self.helper.simple_parse('mnt_keys', network)
                        self.helper.simple_parse('name', network, ['whois-registrant-name'])
                        self.helper.simple_parse('notify_email', network, ['whois-registrant-email'])
                        self.helper.simple_parse('org', network)
                        self.helper.simple_parse('other', network)
                        self.helper.simple_parse('parent', network)
                        self.helper.simple_parse('parent_id', network)
                        self.helper.simple_parse('parent_id', network)
                        self.helper.simple_parse('phone', network, ['whois-registrant-phone'])
                        self.helper.simple_parse('range', network)
                        self.helper.simple_parse('ref', contact)
                        self.helper.simple_parse('remarks', contact)
                        self.helper.simple_parse('source', contact)
                        self.helper.simple_parse('status', contact)
                        self.helper.simple_parse('updated_date', contact)

        else:
            self.helper.multiplex_atrb(results, ['email'], 'whois-registrant-email')
            if self.helper.multiplex_atrb_result != '':
                self.helper.append_unique_payload(self.helper.multiplex_atrb_result)
            self.helper.multiplex_atrb(results, ['org'], 'whois-registrant-org')
            if self.helper.multiplex_atrb_result != '':
                self.helper.append_unique_payload(self.helper.multiplex_atrb_result)
            self.helper.multiplex_atrb(results, ['country'], 'whois-registrant-country')
            if self.helper.multiplex_atrb_result != '':
                self.helper.append_unique_payload(self.helper.multiplex_atrb_result)
            self.helper.multiplex_atrb(results, ['phone'], 'whois-registrant-phone')
            if self.helper.multiplex_atrb_result != '':
                self.helper.append_unique_payload(self.helper.multiplex_atrb_result)
            self.helper.multiplex_atrb(results, ['fax'], 'whois-registrant-phone')
            if self.helper.multiplex_atrb_result != '':
                self.helper.append_unique_payload(self.helper.multiplex_atrb_result)
            self.helper.multiplex_atrb(results, ['name'], 'whois-registrant-name')
            if self.helper.multiplex_atrb_result != '':
                self.helper.append_unique_payload(self.helper.multiplex_atrb_result)

            self.helper.multiplex_atrb(results, ['city'], 'text')
            if self.helper.multiplex_atrb_result != '':
                self.helper.append_unique_payload(self.helper.multiplex_atrb_result)
            self.helper.multiplex_atrb(results, ['country'], 'text')
            if self.helper.multiplex_atrb_result != '':
                self.helper.append_unique_payload(self.helper.multiplex_atrb_result)
            self.helper.multiplex_atrb(results, ['state'], 'text')
            if self.helper.multiplex_atrb_result != '':
                self.helper.append_unique_payload(self.helper.multiplex_atrb_result)
            self.helper.multiplex_atrb(results, ['postal'], 'text')
            if self.helper.multiplex_atrb_result != '':
                self.helper.append_unique_payload(self.helper.multiplex_atrb_result)
            self.helper.multiplex_atrb(results, ['street'], 'text')
            if self.helper.multiplex_atrb_result != '':
                self.helper.append_unique_payload(self.helper.multiplex_atrb_result)

            self.helper.simple_parse('registrar', results, ['whois-registrar'])
            self.helper.simple_parse('created_date', results, ['whois-creation-date'])
            if self.helper.safe_get(results, 'created_date') and self.helper.safe_get_result != '':
                age = self.helper.calculate_age(self.helper.safe_get_result)
                self.helper.append_unique_payload({'types': ['text'], 'categories': ['External analysis'],
                                                   'values': {'domain age': '{0} created {1} ago'.format(q, age)},
                                                   'comment': 'domain age from DomainTools',
                                                   'tags': ['DomainTools', 'domain age']})
                # print("created_date: {0} -> {1}".format(self.helper.safe_get_result, age))
            self.helper.simple_parse('other_properties', results)

        return True

    def whois(self, query):
        if 'whois' not in self.svc_enabled or self.svc_enabled['whois'] <= 0:
            if self.plugin.debug:
                self.log.debug("whois: service disabled or over monthly limit")

        if self.plugin.module['name'] == 'DomainTools-Historic':
            return True

        method = self.api.whois(query)
        results = method.data()
        results = results['response']
        if method._status != 200:
            return True
        if self.helper.safe_path(results, ['whois', 'registrant']) and self.helper.safe_path_result != '':
            self.helper.append_unique_payload({'types': ['whois-registrant-name'],
                                               'values': {'registrant name': self.helper.safe_path_result},
                                               'comment': 'registrant name from DomainTools',
                                               'tags': ['DomainTools', 'whois', 'registrant name']})

        if self.helper.safe_path(results, ['whois', 'registration', 'created']) and self.helper.safe_path_result != '':
            self.helper.append_unique_payload({'types': ['whois-creation-date'],
                                               'values': {'creation date': self.helper.safe_path_result},
                                               'comment': 'creation date from DomainTools',
                                               'tags': ['DomainTools', 'whois', 'creation date']})

        return True

    def domain_profile(self, query):
        if 'domain-profile' not in self.svc_enabled or self.svc_enabled['domain-profile'] <= 0:
            if self.plugin.debug:
                self.log.debug("domain-profile: service disabled or over monthly limit")

        if self.plugin.module['name'] == 'DomainTools-Historic':
            return True

        tldex = tldextract.extract(query.replace('\\/', '/'))
        q = '.'.join(tldex[1:])
        if q == '':
            return True
        method = self.api.domain_profile(q)
        results = method.data()
        results = results['response']
        if method._status != 200:
            return True
        if results.get('error'):
            self.plugin.errors['error'] = results['error']['message']
            return False

        if self.helper.safe_path(results, ['server', 'ip_address']) and self.helper.safe_path_result != '':
            self.helper.append_unique_payload({'types': ['ip-src', 'ip-dst'],
                                               'values': {'domain ip address': self.helper.safe_path_result},
                                               'comment': 'domain ip address from DomainTools',
                                               'tags': ['DomainTools', 'whois', 'domain ip address']})
        if self.helper.safe_path(results, ['registrant', 'name']) and self.helper.safe_path_result != '':
            self.helper.append_unique_payload({'types': ['whois-registrant-name'],
                                               'values': {'registrant name': self.helper.safe_path_result},
                                               'comment': 'registrant name from DomainTools',
                                               'tags': ['DomainTools', 'whois', 'registrant name']})
        if self.helper.safe_path(results, ['registrant', 'email']) and self.helper.safe_path_result != '':
            self.helper.append_unique_payload({'types': ['whois-registrant-email'],
                                               'values': {'registrant email': self.helper.safe_path_result},
                                               'comment': 'registrant email from DomainTools',
                                               'tags': ['DomainTools', 'whois', 'registrant email']})
        if self.helper.safe_path(results, ['registrant', 'domains']) and self.helper.safe_path_result != '':
            self.helper.append_unique_payload({'types': ['text'], 'categories': ['External analysis'],
                                               'values': {
                                                   'registrant domain count': 'registrant has {count} other domains'.format(
                                                       count=self.helper.safe_path_result)},
                                               'comment': 'registrant domain count from DomainTools',
                                               'tags': ['DomainTools', 'whois', 'registrant domain count']})
        if self.helper.safe_path(results, ['server', 'other_domains']) and self.helper.safe_path_result != '':
            self.helper.append_unique_payload({'types': ['text'], 'categories': ['External analysis'],
                                               'values': {
                                                   'co-located domain count': 'IP is shared with {count} other domains'.format(
                                                       count=self.helper.safe_path_result)},
                                               'comment': 'co-located domain count from DomainTools',
                                               'tags': ['DomainTools', 'co-located domain count']})
        if self.helper.safe_path(results, ['name_servers']):
            for ns in self.helper.safe_path_result:
                if ns != '':
                    self.helper.append_unique_payload({'types': ['hostname'],
                                                       'values': {'name server': ns['server']},
                                                       'comment': 'name server from DomainTools',
                                                       'tags': ['DomainTools', 'whois', 'nameserver']})
        if self.helper.safe_path(results, ['registration', 'created']) and self.helper.safe_path_result != '':
            self.helper.append_unique_payload({'types': ['whois-creation-date'],
                                               'values': {'creation date': self.helper.safe_path_result},
                                               'comment': 'creation date from DomainTools',
                                               'tags': ['DomainTools', 'whois', 'creation date']})
        if self.helper.safe_path(results, ['registration', 'registrar']) and self.helper.safe_path_result != '':
            self.helper.append_unique_payload({'types': ['whois-registrar'],
                                               'values': {'registrar': self.helper.safe_path_result},
                                               'comment': 'registrar from DomainTools',
                                               'tags': ['DomainTools', 'whois', 'registrar']})
        return True

    def reputation(self, query):
        if 'reputation' not in self.svc_enabled or self.svc_enabled['reputation'] <= 0:
            if self.plugin.debug:
                self.log.debug("reputation: service disabled or over monthly limit")

        if self.plugin.module['name'] == 'DomainTools-Historic':
            return True

        tldex = tldextract.extract(query.replace('\\/', '/'))
        if self.helper.module_has_type('expansion'):
            method = self.api.reputation('.'.join(tldex[1:]), include_reasons=True)
        else:
            method = self.api.reputation('.'.join(tldex[1:]))
        results = method.data()
        results = results['response']

        if method._status != 200:
            return True
        if results.get('error'):
            self.errors['error'] = results['error']['message']
            return False

        self.helper.simple_parse('risk_score', results, ['text'], 'domain reputation score from DomainTools',
                                 ['DomainTools', 'whois', 'domain reputation score'], 'domain reputation score')
        # self.helper.simple_parse('reasons', pw, ['text'], 'domain reputation score reasons from DomainTools',
        #                         ['DomainTools', 'whois', 'domain reputation score reasons'], 'domain reputation score reasons')
        if self.helper.safe_get(results, 'reasons'):
            reasons = list()
            for item in self.helper.safe_get_result:
                if type(item) is dict:
                    for dict_key in item:
                        reasons.append('{0}: {1}'.format(dict_key, self.helper.safe_get_result[dict_key]))
                else:
                    reasons.append(item)

            if len(reasons) > 0:
                self.helper.append_unique_payload({'types': ['text'], 'categories': ['External analysis'], 'values': {
                    'domain reputation score reason': ', '.join(reasons)},
                                                   'comment': 'domain reputation score reason from DomainTools',
                                                   'tags': ['DomainTools', 'domain reputation score reason']})
        return True

    def risk(self, query):
        if 'risk' not in self.svc_enabled or self.svc_enabled['risk'] <= 0:
            if self.plugin.debug:
                self.log.debug("risk: service disabled or over monthly limit")

        if self.plugin.module['name'] == 'DomainTools-Historic':
            return True

        tldex = tldextract.extract(query.replace('\\/', '/'))
        q = '.'.join(tldex[1:])
        if q == '':
            return True

        method = self.api._results('risk', '/v1/risk', domain=q)
        results = method.data()
        results = results['response']
        if method._status != 200:
            return True
        if results.get('error'):
            self.errors['error'] = results['error']['message']
            return False

        self.helper.simple_parse('risk_score', results)
        # self.helper.simple_parse(_what='components', _from_where=pw, _parent='risk score')
        if self.helper.safe_get(results, 'components'):
            reasons = list()
            for item in self.helper.safe_get_result:
                for dict_key in item:
                    reasons.append('{0}: {1}'.format(dict_key, item[dict_key]))
                if len(reasons) > 0:
                    self.helper.append_unique_payload(
                        {'types': ['text'], 'categories': ['External analysis'], 'values': {
                            'risk score reason': ', '.join(reasons)},
                         'comment': 'risk score reason from DomainTools',
                         'tags': ['DomainTools', 'risk score reason']})
        return True

    def reverse_ip(self, query):
        if 'reverse-ip' not in self.svc_enabled or self.svc_enabled['reverse-ip'] <= 0:
            if self.plugin.debug:
                self.log.debug("reverse-ip: service disabled or over monthly limit")

        if self.plugin.module['name'] == 'DomainTools-Historic':
            return True

        tldex = tldextract.extract(query.replace('\\/', '/'))
        q = '.'.join(tldex[1:])
        if q == '':
            return True

        if self.helper.module_has_type('expansion'):
            method = self.api.reverse_ip(query)
        else:
            method = self.api.reverse_ip(query, limit=0)
            results = method.data()
            results = results['response']

        if method._status != 200:
            return True
        if results.get('error'):
            self.errors['error'] = results['error']['message']
            return False

        if self.helper.safe_get(results, 'ip_addresses'):
            if type(self.helper.safe_get_result) is list:
                for item in self.helper.safe_get_result:
                    if item['domain_count'] != '':
                        self.helper.append_unique_payload(
                            {'types': ['text'], 'categories': ['External analysis'], 'values': {
                                'co-located domain count': '{0} is shared with {count} other domains'.format(q, item[
                                    'domain_count'])},
                             'comment': 'co-located domain count from DomainTools',
                             'tags': ['DomainTools', 'co-located domain count']})

                    if self.helper.module_has_type('expansion'):
                        limit = int(self.plugin.config.get('results_limit'))
                        for d in item['domain_names']:
                            if limit == 0:
                                break
                            limit = limit - 1
                            if d != '':
                                self.helper.append_unique_payload({'types': ['domain'],
                                                                   'values': {'reverse ip domain': d},
                                                                   'comment': 'reverse ip domain from DomainTools',
                                                                   'tags': ['DomainTools', 'reverse ip domain']})
                        if item['ip_address'] != query and item['ip_address'] != '':
                            self.helper.append_unique_payload({'types': ['ip-src', 'ip-dst'],
                                                               'values': {'reverse ip': item['ip_address']},
                                                               'comment': 'reverse ip from DomainTools',
                                                               'tags': ['DomainTools', 'reverse ip']})
            else:
                if self.helper.safe_get_result['domain_count'] != '':
                    self.helper.append_unique_payload(
                        {'types': ['text'], 'categories': ['External analysis'], 'values': {
                            'co-located domain count': '{0} is shared with {count} other domains'.format(q, count=
                            self.helper.safe_get_result['domain_count'])},
                         'comment': 'co-located domain count from DomainTools',
                         'tags': ['DomainTools', 'co-located domain count']})
                if self.helper.module_has_type('expansion'):
                    limit = int(self.plugin.config.get('results_limit'))
                    for d in self.helper.safe_get_result['domain_names']:
                        if limit == 0:
                            break
                        limit = limit - 1
                        if d != '':
                            self.helper.append_unique_payload({'types': ['domain'],
                                                               'values': {'reverse ip domain': d},
                                                               'comment': 'reverse ip domain from DomainTools',
                                                               'tags': ['DomainTools', 'reverse ip domain']})
        return True

    def reverse_whois(self, query):
        if 'reverse-whois' not in self.svc_enabled or self.svc_enabled['reverse-whois'] <= 0:
            if self.plugin.debug:
                self.log.debug("reverse-whois: service disabled or over monthly limit")

        if self.plugin.module['name'] == 'DomainTools-Historic':
            return True

        if self.helper.module_has_type('expansion'):
            method = self.api.reverse_whois(query, mode='purchase')
        else:
            method = self.api.reverse_whois(query, mode='quote')
        results = method.data()
        results = results['response']
        if method._status != 200:
            return True
        if results.get('error'):
            self.errors['error'] = results['error']['message']
            return False

        if self.helper.safe_get(results, 'domains'):
            for domain in self.helper.safe_get_result:
                if domain != '':
                    self.helper.append_unique_payload({'types': ['domain'], 'values': {'reverse whois domain': domain},
                                                       'comment': 'reverse whois domain from DomainTools',
                                                       'tags': ['DomainTools', 'reverse whois domain']})
        if self.helper.safe_get(results, 'domain_count'):
            if 'current' in self.helper.safe_get_result:
                self.helper.append_unique_payload({'types': ['text'], 'categories': ['External analysis'], 'values': {
                    'current domain count': self.helper.safe_get_result['current']},
                                                   'comment': 'domain count current from DomainTools',
                                                   'tags': ['DomainTools', 'reverse whois domain']})
            if 'historic' in self.helper.safe_get_result:
                self.helper.append_unique_payload({'types': ['text'], 'categories': ['External analysis'], 'values': {
                    'historic domain count': self.helper.safe_get_result['historic']},
                                                   'comment': 'historic domain count from DomainTools',
                                                   'tags': ['DomainTools', 'reverse whois']})
        return True

    def host_domains(self, query):
        if 'reverse-ip' not in self.svc_enabled or self.svc_enabled['reverse-ip'] <= 0:
            if self.plugin.debug:
                self.log.debug("reverse-ip: service disabled or over monthly limit")

        if self.plugin.module['name'] == 'DomainTools-Historic':
            return True

        if self.helper.module_has_type('expansion'):
            method = self.api.host_domains(query)
        else:
            method = self.api.host_domains(query, limit=0)
        results = method.data()
        results = results['response']
        if method._status != 200:
            return True
        if results.get('error'):
            self.errors['error'] = results['error']['message']
            return False

        if self.helper.safe_get(results, 'ip_addresses'):
            if self.helper.safe_get_result['ip_address'] != '':
                self.helper.append_unique_payload({'types': ['text'], 'categories': ['External analysis'], 'values': {
                    'co-located domain count': self.helper.safe_get_result['domain_count']},
                                                   'comment': 'co-located domain count from DomainTools',
                                                   'tags': ['DomainTools', 'co-located domain count']})

                if self.helper.module_has_type('expansion'):
                    limit = int(self.plugin.config.get('results_limit'))
                    for d in self.helper.safe_get_result['domain_names']:
                        if limit == 0:
                            break
                        limit = limit - 1
                        if d != '':
                            self.helper.append_unique_payload({'types': ['domain'],
                                                               'values': {'co-located domain': d},
                                                               'comment': 'co-located domain from DomainTools',
                                                               'tags': ['DomainTools', 'co-located domain']})
        return True

    def hosting_history(self, query):
        if 'hosting-history' not in self.svc_enabled or self.svc_enabled['hosting-history'] <= 0:
            if self.plugin.debug:
                self.log.debug("hosting-history: service disabled or over monthly limit")

        if self.plugin.module['name'] != 'DomainTools-Historic':
            return True

        tldex = tldextract.extract(query.replace('\\/', '/'))
        q = '.'.join(tldex[1:])
        if q == '':
            return True

        method = self.api.hosting_history(q)
        results = method.data()
        results = results['response']
        if method._status != 200:
            return
        if results.get('error'):
            self.errors['error'] = results['error']['message']
            return False

        if self.helper.safe_get(results, 'ip_history'):
            for item in self.helper.safe_get_result:
                if item['pre_ip'] is not None and item['pre_ip'] != '':
                    self.helper.append_unique_payload({'types': ['ip-src', 'ip-dst'], 'values': {
                        'ip': item['pre_ip']},
                                                       'comment': 'record date: {0}'.format(item['actiondate']),
                                                       'tags': ['DomainTools', 'hosting history', 'whois', 'ip',
                                                                'historic']})
                if item['post_ip'] is not None and item['post_ip'] != '':
                    self.helper.append_unique_payload({'types': ['ip-src', 'ip-dst'], 'values': {
                        'ip': item['post_ip']},
                                                       'comment': 'record date: {0}'.format(item['actiondate']),
                                                       'tags': ['DomainTools', 'hosting history', 'whois', 'ip',
                                                                'historic']})

        if self.helper.safe_get(results, 'nameserver_history'):
            for item in self.helper.safe_get_result:
                if item['pre_mns'] is not None and item['pre_mns'] != '':
                    self.helper.append_unique_payload({'types': ['hostname'], 'values': {
                        'nameserver': item['pre_mns']},
                                                       'comment': 'record date: {0}'.format(item['actiondate']),
                                                       'tags': ['DomainTools', 'hosting history', 'whois', 'nameserver',
                                                                'historic']})
                if item['post_mns'] is not None and item['post_mns'] != '':
                    self.helper.append_unique_payload({'types': ['hostname'], 'values': {
                        'nameserver': item['post_mns']},
                                                       'comment': 'record date: {0}'.format(item['actiondate']),
                                                       'tags': ['DomainTools', 'hosting history', 'whois', 'nameserver',
                                                                'historic']})

        if self.helper.safe_get(results, 'registrar_history'):
            for item in self.helper.safe_get_result:
                if item['registrar'] is not None and item['registrar'] != '':
                    self.helper.append_unique_payload({'types': ['whois-registrar'], 'values': {
                        'registrar': item['registrar']},
                                                       'comment': 'record date: {0}'.format(item['date_lastchecked']),
                                                       'tags': ['DomainTools', 'hosting history', 'registrar',
                                                                'historic']})
        return True

    def whois_history(self, query):
        if 'whois-history' not in self.svc_enabled or self.svc_enabled['whois-history'] <= 0:
            if self.plugin.debug:
                self.log.debug("whois-history: service disabled or over monthly limit")

        if self.plugin.module['name'] != 'DomainTools-Historic':
            return True

        tldex = tldextract.extract(query.replace('\\/', '/'))
        q = '.'.join(tldex[1:])
        if q == '':
            return True

        method = self.api.whois_history(q)
        results = method.data()
        results = results['response']
        if method._status != 200:
            return True
        if results.get('error'):
            self.errors['error'] = results['error']['message']
            return False

        if self.helper.safe_get(results, 'history'):
            for item in self.helper.safe_get_result:
                matches = re.findall(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", item['whois']['record'])
                for match in list(set(matches)):
                    if match != '':
                        self.helper.append_unique_payload({'types': ['whois-registrant-email'], 'values': {
                            'email': match},
                                                           'comment': 'record date: {0}'.format(item['date']),
                                                           'tags': ['DomainTools', 'whois history']})
        return True

