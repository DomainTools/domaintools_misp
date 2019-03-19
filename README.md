# DomainTools MISP Modules


The [DomainTools](https://domaintools.com) MISP modules extend the MISP hover and expansion features to show domain name profiles and discover connected domains. They are powered by the DomainTools Iris and DomainTools Enterprise APIs.

Complete details including a demo video are available at [https://domaintools.com/misp](https://domaintools.com/misp).

## Iris Modules
These modules work with the DomainTools Iris Investigate API and represent the latest generation of DomainTools capabilities for MISP. They are recommended for all new deployments.

### DomainTools-Iris-Analyze
The Analyze module is designed for MISP tooltip or hover actions on domain names. It provides:
* Domain age
* Registrar
* IP address
* IP country and ISP
* Domain Risk Score, with classifier scores
* Fields with potential Guided Pivots to map connected infrastructure.

### DomainTools-Iris-Pivot
The Pivot module is designed for MISP enrichment actions on domains, IPs, emails, SSL hash, registrar and registrant. 

With domains, the module returns virtually every field from the Iris dataset and maps them to MISP datatypes. Also included are tags and comments that show which attributes would make the best pivots.

For other supported types, the module delivers a list of domain names that share the same attribute (i.e. shared hosting on an IP or re-using the same SSL hash). This helps discover connected infrastructure.

### DomainTools-Iris-Import
The Import module brings domain names from an investigation in the DomainTools Iris UI directly into MISP. It uses the Iris search hash to access the search and retrieve the results with the Iris Investigate API.

## Get Started
### Installation Instructions

    pip install domaintools_api
    pip install domaintools_misp


To use the modules with the misp-modules architecture supporting the -m module syntax, modify the misp-modules startup and use the new -m flag: 
    misp-modules -m domaintools_misp

This will cause the misp-modules to dynamically load the domaintools_misp modules and inject them into the available modules


To use the modules with the misp-modules prior architecture:

    rm /path/to/python/dist/misp_modules/modules/expansion/domaintools.py
    cp /path/to/python/dist/domaintools_misp/install/modules/DomainTools-Analyze.py /path/to/python/dist/misp_modules/modules/expansion/
    cp /path/to/python/dist/domaintools_misp/install/modules/DomainTools-Pivot.py /path/to/python/dist/misp_modules/modules/expansion/
    cp /path/to/python/dist/domaintools_misp/install/modules/DomainTools-Historic.py /path/to/python/dist/misp_modules/modules/expansion/


## Enterprise API Modules
NOTE: These modules require specialized API endpoints that are not available with a DomainTools Iris subscription. Contact us to learn how to get access to them. (EnterpriseSupport at DomainTools dot com).

### DomainTools-Analyze
The DomainTools Analyze module is Optimized for MISP hover-actions, but can also be used for expansions. It provides essential Whois data, a domain name reputation score, and counts of related domains

### DomainTools-Pivot
The DomainTools Pivot module expands domains and hostnames to include a complete set of Whois attributes, plus reputation scores and counts of related domains. The Pivot module will also expand email addresses to a list of other domains that share the same contact information, and expand IP addresses to the list of other domains pointed to the same IP.

### DomainTools-Historic
The DomainTools Historic module accesses historical Whois and hosting history to expand domain names to lists of registrars, IPs and emails historically connected with that domain.

