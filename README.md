# DomainTools MISP Modules

The [DomainTools](https://domaintools.com) MISP modules extend the MISP hover and expansion features to show domain name profiles and discover connected domains. They are powered by the DomainTools Iris and DomainTools Enterprise APIs.

Complete details including a demo video are available at [https://www.domaintools.com/integrations/misp/](https://www.domaintools.com/integrations/misp/).

For more detailed instructions, please see the user guide at [https://www.domaintools.com/wp-content/uploads/DomainTools-For-MISP_2.0_App-User-Guide.pdf](https://www.domaintools.com/wp-content/uploads/DomainTools-For-MISP_2.0_App-User-Guide.pdf).

## Iris Modules

These modules work with the DomainTools Iris Investigate API and represent the latest generation of DomainTools capabilities for MISP. They are recommended for all new deployments.

### DomainTools-Iris-Investigate

- Designed for MISP tooltip or hover actions on domain names
- Provides risk scoring, domain age, hosting, Whois, MX and related infrastructure for a domain.
- Guided Pivot counts help investigators identify connected attributes to other domain infrastructure
- Requires Iris Investigate account provisioning

### DomainTools-Iris-Enrich

- Optimized for high-volume domain enrichment, providing Risk scoring, Hosting, Whois, MX and related infrastructure information for a domain.
- Requires Iris Enrich account provisioning

### DomainTools-Iris-Pivot

- Enriches domain attributes with nearly every available field from the Iris Investigate API.
- Includes complete Risk Score data, with component scores and evidence when available.
- Adds Guided Pivot counts to attribute comments.
- Tags attributes as potential Guided Pivots when connections are shared with fewer than 300 domains (this can be configured in the module attributes).
- Enables pivots on IPs, SSL hashes, nameserver hostnames, and registrant email addresses.
- Requires Iris Investigate account provisioning

### DomainTools-Iris-Import

- Import domains from the Iris Investigate Pivot Engine directly to a MISP event
- Export an investigation from the Iris Investigate UI by copying the search hash (Menu -> Search -> Filters -> Export), importing a list of up to 5000 domains as indicators into MISP
- Requires Iris Investigate account provisioning

### DomainTools-Iris-Detect

- Imports newly discovered and/or newly changed domains from DomainTools Iris Detect product.
- Set up and manage monitored terms using the Iris Detect UI (https://iris.domaintools.com/detect/) then automatically import them into MISP using this module.
- Requires Iris Detect account provisioning

## Get Started

### Installation Instructions

    pip install domaintools_api
    pip install domaintools_misp

To use the modules with the misp-modules architecture supporting the -c module syntax, modify the misp-modules startup and use the new -c flag:

    rm /path/to/python/dist/misp_modules/modules/expansion/domaintools.py
    misp-modules -c /path/to/python/dist/domaintools_misp/install/modules/

This will cause the misp-modules to dynamically load the domaintools_misp custom modules and inject them into the available modules

To use the modules with the misp-modules prior architecture:

    rm /path/to/python/dist/misp_modules/modules/expansion/domaintools.py
    cp /path/to/python/dist/domaintools_misp/install/modules/expansion/DomainTools-Analyze.py /path/to/python/dist/misp_modules/modules/expansion/
    cp /path/to/python/dist/domaintools_misp/install/modules/expansion/DomainTools-Pivot.py /path/to/python/dist/misp_modules/modules/expansion/
    cp /path/to/python/dist/domaintools_misp/install/modules/expansion/DomainTools-Historic.py /path/to/python/dist/misp_modules/modules/expansion/
    cp /path/to/python/dist/domaintools_misp/install/modules/expansion/DomainTools-Iris-Pivot.py /path/to/python/dist/misp_modules/modules/expansion/
    cp /path/to/python/dist/domaintools_misp/install/modules/expansion/DomainTools-Iris-Investigate.py /path/to/python/dist/misp_modules/modules/expansion/
    cp /path/to/python/dist/domaintools_misp/install/modules/expansion/DomainTools-Iris-Enrich.py /path/to/python/dist/misp_modules/modules/expansion/
    cp /path/to/python/dist/domaintools_misp/install/modules/expansion/DomainTools-Iris-Import.py /path/to/python/dist/misp_modules/modules/expansion/
    cp /path/to/python/dist/domaintools_misp/install/modules/expansion/DomainTools-Iris-Detect.py /path/to/python/dist/misp_modules/modules/expansion/

## Enterprise API Modules

NOTE: These modules require specialized API endpoints that are not available with a DomainTools Iris subscription. Contact us to learn how to get access to them. (EnterpriseSupport at DomainTools dot com).

### DomainTools-Analyze

- This module is superseded by the Iris Investigate module but remains here for backward compatibility. Optimized for MISP hover actions, the Analyze capability provides Whois data, a Domain Risk Score and counts of connected domains to help give quick context on an indicator to inform an interesting pivot and map connected infrastructure.
- Leverages the following DomainTools endpoints: Parsed Whois, Domain Profile, Risk, Reverse IP, Reverse Whois

### DomainTools-Pivot

- This module is superseded by the Iris Pivot module, but remains here for backward compatibility. Optimized for enrichment actions, the Pivot capability provides additional context on indicators by automatically building out a list of connected infrastructure from the counts presented in the Analyze capability.
- The Pivot module will also expand email addresses to a list of other domains that share the same contact information, and expand IP addresses to the list of other domains pointed to the same IP.
- Leverages the following DomainTools endpoints: Parsed Whois, Domain Profile, Risk, Reverse IP, Reverse Whois

### DomainTools-Historic

- The Historic capability will act on Domains or URLs to find historical context by expanding domain names to lists of registrars, IPs and emails historically connected with that indicator
- Leverages the following DomainTools endpoints: Whois History, Hosting History, Domain Profile, Reverse IP, Reverse Whois, Parsed Whois, Whois
