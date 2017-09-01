"""Tests for misp"""
import pytest
import json
from domaintools_misp.analyze import dt_misp_module_analyze
from domaintools_misp.pivot import dt_misp_module_pivot
from domaintools_misp.historic import dt_misp_module_historic

def test_analyze_whois_registrant_email():
    q = json.loads('{"module":"DomainTools-Analyze","domain":"axwjgj.com","event_id":"734"}')
    with open('.config') as config:    
        q['config'] = json.load(config)
    
    dtmm = dt_misp_module_pivot()
    response = dtmm.process_request(json.dumps(q))
    the_test = False
    assert 'results' in response
    assert len(response['results']) > 0
    for record in response['results']:
        if 'whois-registrant-email' in record['values']:
            the_test = True
    assert the_test is True

def test_analyze_whois_registrant_phone():
    q = json.loads('{"module":"DomainTools-Analyze","domain":"axwjgj.com","event_id":"734"}')
    with open('.config') as config:    
        q['config'] = json.load(config)
    dtmm = dt_misp_module_pivot()
    response = dtmm.process_request(json.dumps(q))
    the_test = False
    assert 'results' in response
    assert len(response['results']) > 0
    for record in response['results']:
        if 'whois-registrant-phone' in record['values']:
            the_test = True
    assert the_test is True

def test_analyze_whois_registrant_name():
    q = json.loads('{"module":"DomainTools-Analyze","domain":"axwjgj.com","event_id":"734"}')
    with open('.config') as config:    
        q['config'] = json.load(config)
    dtmm = dt_misp_module_pivot()
    response = dtmm.process_request(json.dumps(q))
    the_test = False
    assert 'results' in response
    assert len(response['results']) > 0
    for record in response['results']:
        if 'whois-registrant-name' in record['values']:
            the_test = True
    assert the_test is True

def test_analyze_colocated_count():
    q = json.loads('{"module":"DomainTools-Analyze","domain":"axwjgj.com","event_id":"734"}')
    with open('.config') as config:    
        q['config'] = json.load(config)
    dtmm = dt_misp_module_pivot()
    response = dtmm.process_request(json.dumps(q))
    the_test = False
    assert 'results' in response
    assert len(response['results']) > 0
    for record in response['results']:
        if 'co-located domain count' in record['values']:
            the_test = True
    assert the_test is True

def test_analyze_risk_score():
    q = json.loads('{"module":"DomainTools-Analyze","domain":"axwjgj.com","event_id":"734"}')
    with open('.config') as config:    
        q['config'] = json.load(config)
    dtmm = dt_misp_module_pivot()
    response = dtmm.process_request(json.dumps(q))
    the_test = False
    assert 'results' in response
    assert len(response['results']) > 0
    for record in response['results']:
        if 'risk score' in record['values']:
            the_test = True
    assert the_test is True

def test_pivot_whois_registrant_name():
    q = json.loads('{"module":"DomainTools-Pivot","domain":"axwjgj.com","event_id":"734"}')
    with open('.config') as config:    
        q['config'] = json.load(config)
    dtmm = dt_misp_module_pivot()
    response = dtmm.process_request(json.dumps(q))
    the_test = False
    assert 'results' in response
    assert len(response['results']) > 0
    for record in response['results']:
        if 'whois-registrant-name' in record['values']:
            the_test = True
    assert the_test is True

def test_pivot_colocated_count():
    q = json.loads('{"module":"DomainTools-Pivot","domain":"axwjgj.com","event_id":"734"}')
    with open('.config') as config:    
        q['config'] = json.load(config)
    dtmm = dt_misp_module_pivot()
    response = dtmm.process_request(json.dumps(q))
    the_test = False
    assert 'results' in response
    assert len(response['results']) > 0
    for record in response['results']:
        if 'co-located domain count' in record['values']:
            the_test = True
    assert the_test is True

def test_pivot_risk_score():
    q = json.loads('{"module":"DomainTools-Pivot","domain":"axwjgj.com","event_id":"734"}')
    with open('.config') as config:    
        q['config'] = json.load(config)
    dtmm = dt_misp_module_pivot()
    response = dtmm.process_request(json.dumps(q))
    the_test = False
    assert 'results' in response
    assert len(response['results']) > 0
    for record in response['results']:
        if 'risk score' in record['values']:
            the_test = True
    assert the_test is True

def test_historic_hosting_history():
    q = json.loads('{"module":"DomainTools-Historic","domain":"axwjgj.com","event_id":"734"}')
    with open('.config') as config:    
        q['config'] = json.load(config)
    dtmm = dt_misp_module_historic()
    response = dtmm.process_request(json.dumps(q))
    the_test = False
    assert 'results' in response
    assert len(response['results']) > 0
    for record in response['results']:
        if 'ip' in record['values']:
            the_test = True
    assert the_test is True

def test_historic_whois_registrant_email():
    q = json.loads('{"module":"DomainTools-Historic","domain":"axwjgj.com","event_id":"734"}')
    with open('.config') as config:    
        q['config'] = json.load(config)
    dtmm = dt_misp_module_pivot()
    response = dtmm.process_request(json.dumps(q))
    the_test = False
    assert 'results' in response
    assert len(response['results']) > 0
    for record in response['results']:
        if 'whois-registrant-email' in record['values']:
            the_test = True
    assert the_test is True