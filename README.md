DomainTools MISP Modules
====================================

This officially supported open-source python library provides the following modules for MISP:

DomainTools-Analyze
-------------------
    The DomainTools Analyze module is Optimized for MISP hover-actions, but can also be used for expansions. It provides essential Whois data, a domain name reputation score, and counts of related domains

DomainTools-Pivot
-----------------
    The DomainTools Pivot module expands domains and hostnames to include a complete set of Whois attributes, plus reputation scores and counts of related domains. The Pivot module will also expand email addresses to a list of other domains that share the same contact information, and expand IP addresses to the list of other domains pointed to the same IP.

DomainTools-Historic
--------------------
    The DomainTools Historic module accesses historical Whois and hosting history to expand domain names to lists of registrars, IPs and emails historically connected with that domain.


Installation Instructions
-

    pip install domaintools_api
    pip install domaintools_misp


To use the modules with the misp-modules architecture supporting the -m module syntax:
-
    modify the misp-modules startup to use the new -m flag: misp-modules -m domaintools_misp
    this will cause the misp-modules to dynamically load the domaintools_misp modules and inject them into the available modules


To use the modules with the misp-modules prior architecture:
-
    rm /path/to/python/dist/misp_modules/modules/expansion/domaintools.py
    cp /path/to/python/dist/domaintools_misp/install/modules/DomainTools-Analyze.py /path/to/python/dist/misp_modules/modules/expansion/
    cp /path/to/python/dist/domaintools_misp/install/modules/DomainTools-Pivot.py /path/to/python/dist/misp_modules/modules/expansion/
    cp /path/to/python/dist/domaintools_misp/install/modules/DomainTools-Historic.py /path/to/python/dist/misp_modules/modules/expansion/

