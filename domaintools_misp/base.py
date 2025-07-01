import base64
import hashlib
import json
import logging
import re
import sys
import tldextract
import time

from datetime import datetime
from dateutil import parser

from domaintools import API
from domaintools.exceptions import NotFoundException
from domaintools_misp.constants import (
    ATTRIBUTE_TYPES_MAP,
    ESCALATION_TYPES_MAP,
    GUIDED_PIVOT_COUNT_MAX,
    GUIDED_PIVOT_COUNT_MIN,
    PIVOT_MAP,
    RISK_SCORE_RANGES_MAP,
)


class dt_module_helpers:
    def __init__(self, plugin):
        self.plugin = plugin

    def append_unique_payload(self, payload):
        m = hashlib.md5()
        for k in payload["values"]:
            if k == "":
                continue

            if payload["values"][k] == "":
                if len(payload["values"]) == 1:
                    return
                continue

            m.update("{0}".format(k).encode("utf-8"))
            m.update("{0}".format(payload["values"][k]).encode("utf-8"))

        item = m.hexdigest()
        if item not in self.plugin.unique:
            self.plugin.unique[item] = True
            self.plugin.payload.append(payload)

    def append_unique_value(self, a_list, a_value):
        a_list.append(a_value)
        a_set = set(a_list)
        return list(a_set)

    def module_has_type(self, type):
        for t in self.plugin.module_info["module-type"]:
            if t == type:
                return True
        return False

    def format_age(self, age):
        if age < 60:
            return "{age} seconds".format(age=age)
        elif age < (60 * 60):
            return "{age} minutes".format(age=round(age / 60, 1))
        elif age < (60 * 60 * 24):
            return "{age} hours".format(age=round(age / (60 * 60), 1))
        elif age < (60 * 60 * 24 * 7):
            return "{age} days".format(age=round(age / (60 * 60 * 24), 1))
        elif age < (60 * 60 * 24 * 30):
            return "{age} weeks".format(age=round(age / (60 * 60 * 24 * 7), 1))
        elif age < (60 * 60 * 24 * 365):
            return "{age} months".format(age=round(age / (60 * 60 * 24 * 30), 1))
        else:
            return "{age} years".format(age=round(age / (60 * 60 * 24 * 365), 1))

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
        self.safe_get_result = src.get(key)
        return bool(self.safe_get_result and self.safe_get_result != "")

    def multiplex_atrb(self, src, keys, label):
        self.multiplex_atrb_result = ""
        values = []
        for key in keys:
            if self.safe_path(src, ["contacts", "admin", key]):
                if type(self.safe_path_result) is list:
                    for item in self.safe_path_result:
                        if item != "" and item not in values:
                            self.append_unique_value(values, item)
                else:
                    if self.safe_path_result != "":
                        self.append_unique_value(values, self.safe_path_result)
            if self.safe_path(src, ["contacts", "billing", key]):
                if type(self.safe_path_result) is list:
                    for item in self.safe_path_result:
                        if item != "" and item not in values:
                            self.append_unique_value(values, item)
                else:
                    if self.safe_path_result != "":
                        self.append_unique_value(values, self.safe_path_result)
            if self.safe_path(src, ["contacts", "registrant", key]):
                if type(self.safe_path_result) is list:
                    for item in self.safe_path_result:
                        if item != "" and item not in values:
                            self.append_unique_value(values, item)
                else:
                    if self.safe_path_result != "":
                        self.append_unique_value(values, self.safe_path_result)
            if self.safe_path(src, ["contacts", "tech", key]):
                if type(self.safe_path_result) is list:
                    for item in self.safe_path_result:
                        if item != "":
                            self.append_unique_value(values, item)
                else:
                    if self.safe_path_result != "":
                        self.append_unique_value(values, self.safe_path_result)
        for item in values:
            self.multiplex_atrb_result = {
                "types": ["{key}".format(key=label)],
                "values": {label: item},
                "comment": "{0} from DomainTools".format(label),
                "tags": ["DomainTools", "whois", label],
            }

    def simple_parse(
        self,
        _what,
        _from_where,
        _types=["text"],
        _comment="{0} from DomainTools",
        _tags=["DomainTools", "whois"],
        _label="{0}",
        _categories=["External analysis"],
        _parent=None,
    ):
        if _parent is not None:
            _comment = "{0} -> {1}".format(_parent, _comment)
            _label = "{0} -> {1}".format(_parent, _label)
        if type(_from_where) is dict:
            if _what == "*":
                for dict_key in _from_where:
                    _tags_local = _tags[:]
                    self.simple_parse(
                        dict_key,
                        _from_where,
                        _types,
                        _comment,
                        self.append_unique_value(_tags_local, _what.replace("_", " ")),
                        _label,
                        _categories,
                    )
            elif self.safe_get(_from_where, _what):
                if type(self.safe_get_result) is dict:
                    for dict_key in self.safe_get_result:
                        _tags_local = _tags[:]
                        self.simple_parse(
                            dict_key,
                            self.safe_get_result,
                            _types,
                            _comment.format(_what.replace("_", " ") + " -> {0}"),
                            self.append_unique_value(_tags_local, _what.replace("_", " ")),
                            _label.format(_what.replace("_", " ") + " -> {0}"),
                            _categories,
                        )
                elif type(self.safe_get_result) is list:
                    for item in self.safe_get_result:
                        _tags_local = _tags[:]
                        self.simple_parse(
                            "*",
                            item,
                            _types,
                            _comment.format(_what.replace("_", " ") + " -> {0}"),
                            self.append_unique_value(_tags_local, _what.replace("_", " ")),
                            _label.format(_what.replace("_", " ") + " -> {0}"),
                            _categories,
                        )

                        # self.append_unique_payload({'types': _types, 'values': {_label.format(_what.replace('_',' ')): item}, 'comment': _comment.format(_what.replace('_',' ')), 'tags': self.append_unique_value(_tags_local,_what.replace('_',' ')), 'categories': _categories})
                else:
                    self.append_unique_payload(
                        {
                            "types": _types,
                            "values": {_label.format(_what.replace("_", " ")): self.safe_get_result},
                            "comment": _comment.format(_what.replace("_", " ")),
                            "tags": _tags,
                            "categories": _categories,
                        }
                    )
        elif type(_from_where) is list:
            for item in _from_where:
                _tags_local = _tags[:]
                self.simple_parse(
                    _what,
                    item,
                    _types,
                    _comment.format(_what.replace("_", " ") + " -> {0}"),
                    self.append_unique_value(_tags_local, _what.replace("_", " ")),
                    _label.format(_what.replace("_", " ") + " -> {0}"),
                    _categories,
                )
        else:
            self.append_unique_payload(
                {
                    "types": _types,
                    "values": {_label.format(_what.replace("_", " ")): _from_where},
                    "comment": _comment.format(_what.replace("_", " ")),
                    "tags": _tags,
                    "categories": _categories,
                }
            )

    def iris_add(self, item, type, label, categories=["External analysis"]):
        count = None
        tags = ["DomainTools", "Iris"]
        threshold = int(self.plugin.config.get("guided_pivot_threshold"))

        if self.safe_get(item, "count"):
            count = self.safe_get_result
            comment = "{0} (GP: {1:,}) from DomainTools Iris".format(label, count)
        else:
            comment = "{0} from DomainTools Iris".format(label)

        if count and count < threshold:
            tags.append("Guided Pivot")

        self.simple_parse("value", item, type, comment, tags, label, _categories=categories)

    def iris_address(self, item, label):

        if self.safe_get(item, "name"):
            if label == "Registrant Contact":
                self.iris_add(
                    self.safe_get_result,
                    ["whois-registrant-name"],
                    "{0} Name".format(label),
                    categories=["Attribution"],
                )
            else:
                self.iris_add(self.safe_get_result, ["text"], "{0} Name".format(label))

        if self.safe_get(item, "org"):
            self.iris_add(self.safe_get_result, ["text"], "{0} Org".format(label))
        if self.safe_get(item, "street"):
            self.iris_add(self.safe_get_result, ["text"], "{0} Street".format(label))
        if self.safe_get(item, "state"):
            self.iris_add(self.safe_get_result, ["text"], "{0} State".format(label))
        if self.safe_get(item, "city"):
            self.iris_add(self.safe_get_result, ["text"], "{0} City".format(label))
        if self.safe_get(item, "country"):
            self.iris_add(self.safe_get_result, ["text"], "{0} Country".format(label))
        if self.safe_get(item, "fax"):
            self.iris_add(self.safe_get_result, ["text"], "{0} Fax".format(label))
        if self.safe_get(item, "postal"):
            self.iris_add(self.safe_get_result, ["text"], "{0} Postal".format(label))
        if self.safe_get(item, "phone"):
            self.iris_add(self.safe_get_result, ["text"], "{0} Phone".format(label))

        for email in item["email"]:
            if label == "Registrant Contact":
                self.iris_add(
                    email,
                    ["whois-registrant-email"],
                    "{0} Email".format(label),
                    categories=["Attribution"],
                )
            else:
                self.iris_add(email, ["text"], "{0} Email".format(label))

    def extract_nested_value(self, value, label):
        if not value:
            return

        if type(value) is list:
            for item in value:
                self.extract_nested_value(item, label)
            return

        if type(value) is not dict:
            return

        if "count" in value and value["count"] > GUIDED_PIVOT_COUNT_MIN and value["count"] <= GUIDED_PIVOT_COUNT_MAX:
            self.append_unique_payload(
                {
                    "types": [ATTRIBUTE_TYPES_MAP.get(label, "text")],
                    "categories": ["External analysis"],
                    "values": {"Guided Pivot": f"{label} (~{value['count']} domains share this value.)"},
                    "comment": "Guided Pivot",
                    "tags": ["DomainTools", "Guided Pivot"],
                }
            )
        elif value:
            self.append_unique_payload(
                {
                    "types": [ATTRIBUTE_TYPES_MAP.get(label, "text")],
                    "categories": ["External analysis"],
                    "values": {label.title(): value.get("value")},
                    "comment": f"{label.title()} from Domaintools",
                    "tags": ["DomainTools", label.title()],
                }
            )

    def get_count_or_value(self, iris_property, label):
        for key, value in iris_property.items():
            self.extract_nested_value(value, f"{label} {key}")

    def is_valid_datetime(self, datetime_str, whitelist=("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S+00:00")):
        for fmt in whitelist:
            try:
                datetime.strptime(datetime_str, fmt)
                return True
            except ValueError:
                continue

        return False


class dt_misp_module_base:
    def __init__(self):

        self.misp_attributes = {
            "input": [
                "domain",
                "hostname",
                "url",
                "uri",
                "email-src",
                "email-dst",
                "target-email",
                "whois-registrant-email",
                "whois-registrant-name",
                "whois-registrant-phone",
                "ip-src",
                "ip-dst",
                "whois-creation-date",
                "text",
                "x509-fingerprint-sha1",
            ],
            "output": [
                "whois-registrant-email",
                "whois-registrant-phone",
                "whois-registrant-name",
                "whois-registrar",
                "whois-creation-date",
                "comment",
                "domain",
                "ip-src",
                "ip-dst",
                "text",
            ],
        }

        self.module_config = ["username", "api_key", "results_limit"]
        self.results_limit = 100
        self.guided_pivot_threshold = 300
        self.historic_enabled = False
        self.debug = False
        self.payload = list()
        self.unique = dict()
        self.errors = {"error": "An unknown error has occurred"}
        self.helper = dt_module_helpers(self)
        self.log = logging.getLogger("DomainTools")
        self.log.setLevel(logging.DEBUG)
        self.ch = logging.StreamHandler(sys.stdout)
        self.ch.setLevel(logging.DEBUG)
        self.formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        self.ch.setFormatter(self.formatter)
        self.log.addHandler(self.ch)

    def check_config(self, request):
        """Check the incoming request for valid info."""
        self.config = request.get("config", None)
        if self.config is None:
            self.errors["error"] = "Configuration is missing from the request."
            return False

        if self.config.get("username", None) is None:
            self.errors["error"] = "DomainTools API username is not configured."
            return False

        if self.config.get("api_key", None) is None:
            self.errors["error"] = "DomainTools API key is not configured."
            return False

        if self.helper.module_has_type("expansion") and self.config.get("results_limit", None) is None:
            self.config["results_limit"] = self.results_limit

        if self.helper.module_has_type("expansion") and self.config.get("guided_pivot_threshold", "") == "":
            self.config["guided_pivot_threshold"] = self.guided_pivot_threshold

        self.api = dt_api_adapter_misp(self)
        self.svc_map = {
            "text": [
                self.api.parsed_whois,
                self.api.domain_profile,
                self.api.hosting_history,
                self.api.whois_history,
                self.api.risk,
            ],
            "domain": [
                self.api.parsed_whois,
                self.api.domain_profile,
                self.api.hosting_history,
                self.api.whois_history,
                self.api.risk,
                self.api.iris_hover,
                self.api.iris_pivot,
            ],
            "hostname": [
                self.api.parsed_whois,
                self.api.domain_profile,
                self.api.hosting_history,
                self.api.whois_history,
                self.api.risk,
                self.api.iris_pivot,
            ],
            "url": [
                self.api.parsed_whois,
                self.api.domain_profile,
                self.api.hosting_history,
                self.api.whois_history,
                self.api.risk,
            ],
            "uri": [
                self.api.parsed_whois,
                self.api.domain_profile,
                self.api.hosting_history,
                self.api.whois_history,
                self.api.risk,
            ],
            "email-src": [self.api.reverse_whois, self.api.iris_pivot],
            "email-dst": [self.api.reverse_whois, self.api.iris_pivot],
            "target-email": [self.api.reverse_whois],
            "whois-registrant-email": [self.api.reverse_whois, self.api.iris_pivot],
            "whois-registrant-name": [self.api.reverse_whois, self.api.iris_pivot],
            "whois-registrant-phone": [self.api.reverse_whois],
            "whois-registrar": [self.api.iris_pivot],
            "ip-src": [
                self.api.host_domains,
                self.api.parsed_whois,
                self.api.hosting_history,
                self.api.iris_pivot,
            ],
            "ip-dst": [
                self.api.host_domains,
                self.api.parsed_whois,
                self.api.hosting_history,
                self.api.iris_pivot,
            ],
            "whois-creation-date": [self.api.reverse_whois],
            "data": [
                self.api.iris_import,
                self.api.iris_detect,
            ],
            "x509-fingerprint-sha1": [self.api.iris_pivot],
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
                for type in self.misp_attributes["input"]:
                    if type in request:
                        for svc in self.svc_map[type]:
                            try:
                                svc(request[type], type)
                            except Exception as e:
                                # Catchall exception for code simplication. We're still logging the specific exception name for debugging purposes.
                                self.log.debug(f"API returned a {e.__class__.__name__} response for {request[type]}.")
                                self.errors["error"] = str(e)
                                pass
                        break  # can there realistically be more than one type in a request?

                if self.payload:
                    final_result = {"results": self.payload}
                    if self.errors.get("error") != "An unknown error has occurred":
                        final_result["error"] = self.errors.get("error")

                    return final_result

        except NotFoundException as e:
            self.errors = {"results": "No information found"}

        return self.errors


class dt_api_adapter_misp:
    def __init__(self, plugin):
        self.plugin = plugin
        self.helper = plugin.helper
        self.svc_enabled = dict()
        self.api = API(
            username=plugin.config.get("username"),
            key=plugin.config.get("api_key"),
            app_partner="MISP",
            app_name=plugin.module["name"],
            app_version=plugin.module_info["version"],
        )
        self.account_information = self.api.account_information().data()

        for svc in self.account_information["response"]["products"]:
            if svc["per_month_limit"] is not None:
                self.svc_enabled[svc["id"]] = int(svc["per_month_limit"]) - int(svc["usage"]["month"])

            else:
                self.svc_enabled[svc["id"]] = True

    def parsed_whois(self, query, query_type):
        if "parsed-whois" not in self.svc_enabled or self.svc_enabled["parsed-whois"] <= 0:
            if self.plugin.debug:
                self.plugin.log.debug("parsed-whois: service disabled or over monthly limit")

        if self.plugin.module["name"] == "DomainTools-Historic":
            return True
        if self.plugin.module["name"] == "DomainTools-Iris-Investigate":
            return True
        if self.plugin.module["name"] == "DomainTools-Iris-Enrich":
            return True
        if self.plugin.module["name"] == "DomainTools-Iris-Pivot":
            return True

        tldex = tldextract.extract(query.replace("\\/", "/"))
        q = tldex.top_domain_under_public_suffix
        if q == "":
            return True
        method = self.api.parsed_whois(q)
        results = method.data()
        results = results["response"]
        if method._status != 200:
            return True
        results = results.get("parsed_whois")
        if results.get("source"):
            if self.helper.module_has_type("expansion"):
                if self.helper.safe_get(results, "contacts"):
                    for contact in self.helper.safe_get_result:
                        self.helper.simple_parse("abuse_mailbox", contact, ["email-src", "email-dst"])
                        self.helper.simple_parse("address", contact)
                        self.helper.simple_parse("changed_by", contact)
                        self.helper.simple_parse("descr", contact)
                        self.helper.simple_parse("fax", contact, ["whois-registrant-phone"])
                        self.helper.simple_parse("notify_email", contact, ["whois-registrant-email"])
                        self.helper.simple_parse("phone", contact, ["whois-registrant-phone"])
                        self.helper.simple_parse("remarks", contact)
                        self.helper.simple_parse("contact_keys", contact)
                        self.helper.simple_parse("mnt_keys", contact)
                        self.helper.simple_parse("other", contact)
                        self.helper.simple_parse("country", contact)
                        self.helper.simple_parse("created_date", contact, ["whois-creation-date"])
                        self.helper.simple_parse("id", contact)
                        self.helper.simple_parse("name", contact, ["whois-registrant-name"])
                        self.helper.simple_parse("ref", contact, ["url", "uri"])
                        self.helper.simple_parse("source", contact)
                        self.helper.simple_parse("type", contact)
                        self.helper.simple_parse("updated_date", contact)
                if self.helper.safe_get(results, "networks"):
                    for network in self.helper.safe_get_result:
                        self.helper.simple_parse("asn", network)
                        self.helper.simple_parse("changed_by", network)
                        self.helper.simple_parse("contact_keys", network)
                        self.helper.simple_parse("country", network)
                        self.helper.simple_parse("created_date", network, ["whois-creation-date"])
                        self.helper.simple_parse("customer", network)
                        self.helper.simple_parse("descr", network)
                        self.helper.simple_parse("id", network)
                        self.helper.simple_parse("mnt_keys", network)
                        self.helper.simple_parse("name", network, ["whois-registrant-name"])
                        self.helper.simple_parse("notify_email", network, ["whois-registrant-email"])
                        self.helper.simple_parse("org", network)
                        self.helper.simple_parse("other", network)
                        self.helper.simple_parse("parent", network)
                        self.helper.simple_parse("parent_id", network)
                        self.helper.simple_parse("parent_id", network)
                        self.helper.simple_parse("phone", network, ["whois-registrant-phone"])
                        self.helper.simple_parse("range", network)
                        self.helper.simple_parse("ref", contact)
                        self.helper.simple_parse("remarks", contact)
                        self.helper.simple_parse("source", contact)
                        self.helper.simple_parse("status", contact)
                        self.helper.simple_parse("updated_date", contact)

        else:
            self.helper.multiplex_atrb(results, ["email"], "whois-registrant-email")
            if self.helper.multiplex_atrb_result != "":
                self.helper.append_unique_payload(self.helper.multiplex_atrb_result)
            self.helper.multiplex_atrb(results, ["org"], "whois-registrant-org")
            if self.helper.multiplex_atrb_result != "":
                self.helper.append_unique_payload(self.helper.multiplex_atrb_result)
            self.helper.multiplex_atrb(results, ["country"], "whois-registrant-country")
            if self.helper.multiplex_atrb_result != "":
                self.helper.append_unique_payload(self.helper.multiplex_atrb_result)
            self.helper.multiplex_atrb(results, ["phone"], "whois-registrant-phone")
            if self.helper.multiplex_atrb_result != "":
                self.helper.append_unique_payload(self.helper.multiplex_atrb_result)
            self.helper.multiplex_atrb(results, ["fax"], "whois-registrant-phone")
            if self.helper.multiplex_atrb_result != "":
                self.helper.append_unique_payload(self.helper.multiplex_atrb_result)
            self.helper.multiplex_atrb(results, ["name"], "whois-registrant-name")
            if self.helper.multiplex_atrb_result != "":
                self.helper.append_unique_payload(self.helper.multiplex_atrb_result)

            self.helper.multiplex_atrb(results, ["city"], "text")
            if self.helper.multiplex_atrb_result != "":
                self.helper.append_unique_payload(self.helper.multiplex_atrb_result)
            self.helper.multiplex_atrb(results, ["country"], "text")
            if self.helper.multiplex_atrb_result != "":
                self.helper.append_unique_payload(self.helper.multiplex_atrb_result)
            self.helper.multiplex_atrb(results, ["state"], "text")
            if self.helper.multiplex_atrb_result != "":
                self.helper.append_unique_payload(self.helper.multiplex_atrb_result)
            self.helper.multiplex_atrb(results, ["postal"], "text")
            if self.helper.multiplex_atrb_result != "":
                self.helper.append_unique_payload(self.helper.multiplex_atrb_result)
            self.helper.multiplex_atrb(results, ["street"], "text")
            if self.helper.multiplex_atrb_result != "":
                self.helper.append_unique_payload(self.helper.multiplex_atrb_result)

            self.helper.simple_parse("registrar", results, ["whois-registrar"])
            self.helper.simple_parse("created_date", results, ["whois-creation-date"])
            if self.helper.safe_get(results, "created_date") and self.helper.safe_get_result != "":
                age = self.helper.calculate_age(self.helper.safe_get_result)
                self.helper.append_unique_payload(
                    {
                        "types": ["text"],
                        "categories": ["External analysis"],
                        "values": {"domain age": "{0} created {1} ago".format(q, age)},
                        "comment": "domain age from DomainTools",
                        "tags": ["DomainTools", "domain age"],
                    }
                )
                # print("created_date: {0} -> {1}".format(self.helper.safe_get_result, age))
            self.helper.simple_parse("other_properties", results)

        return True

    def whois(self, query, query_type):
        if "whois" not in self.svc_enabled or self.svc_enabled["whois"] <= 0:
            if self.plugin.debug:
                self.plugin.log.debug("whois: service disabled or over monthly limit")

        if self.plugin.module["name"] == "DomainTools-Historic":
            return True

        method = self.api.whois(query)
        results = method.data()
        results = results["response"]
        if method._status != 200:
            return True
        if self.helper.safe_path(results, ["whois", "registrant"]) and self.helper.safe_path_result != "":
            self.helper.append_unique_payload(
                {
                    "types": ["whois-registrant-name"],
                    "values": {"registrant name": self.helper.safe_path_result},
                    "comment": "registrant name from DomainTools",
                    "tags": ["DomainTools", "whois", "registrant name"],
                }
            )

        if self.helper.safe_path(results, ["whois", "registration", "created"]) and self.helper.safe_path_result != "":
            self.helper.append_unique_payload(
                {
                    "types": ["whois-creation-date"],
                    "values": {"creation date": self.helper.safe_path_result},
                    "comment": "creation date from DomainTools",
                    "tags": ["DomainTools", "whois", "creation date"],
                }
            )

        return True

    def domain_profile(self, query, query_type):
        if "domain-profile" not in self.svc_enabled or self.svc_enabled["domain-profile"] <= 0:
            if self.plugin.debug:
                self.plugin.log.debug("domain-profile: service disabled or over monthly limit")

        if self.plugin.module["name"] == "DomainTools-Historic":
            return True
        if self.plugin.module["name"] == "DomainTools-Iris-Investigate":
            return True
        if self.plugin.module["name"] == "DomainTools-Iris-Enrich":
            return True
        if self.plugin.module["name"] == "DomainTools-Iris-Pivot":
            return True

        tldex = tldextract.extract(query.replace("\\/", "/"))
        q = tldex.top_domain_under_public_suffix
        if q == "":
            return True
        method = self.api.domain_profile(q)
        results = method.data()
        results = results["response"]
        if method._status != 200:
            return True
        if results.get("error"):
            self.plugin.errors["error"] = results["error"]["message"]
            return False

        if self.helper.safe_path(results, ["server", "ip_address"]) and self.helper.safe_path_result != "":
            self.helper.append_unique_payload(
                {
                    "types": ["ip-src", "ip-dst"],
                    "values": {"domain ip address": self.helper.safe_path_result},
                    "comment": "domain ip address from DomainTools",
                    "tags": ["DomainTools", "whois", "domain ip address"],
                }
            )
        if self.helper.safe_path(results, ["registrant", "name"]) and self.helper.safe_path_result != "":
            self.helper.append_unique_payload(
                {
                    "types": ["whois-registrant-name"],
                    "values": {"registrant name": self.helper.safe_path_result},
                    "comment": "registrant name from DomainTools",
                    "tags": ["DomainTools", "whois", "registrant name"],
                }
            )
        if self.helper.safe_path(results, ["registrant", "email"]) and self.helper.safe_path_result != "":
            self.helper.append_unique_payload(
                {
                    "types": ["whois-registrant-email"],
                    "values": {"registrant email": self.helper.safe_path_result},
                    "comment": "registrant email from DomainTools",
                    "tags": ["DomainTools", "whois", "registrant email"],
                }
            )
        if self.helper.safe_path(results, ["registrant", "domains"]) and self.helper.safe_path_result != "":
            self.helper.append_unique_payload(
                {
                    "types": ["text"],
                    "categories": ["External analysis"],
                    "values": {"registrant domain count": "registrant has {count} other domains".format(count=self.helper.safe_path_result)},
                    "comment": "registrant domain count from DomainTools",
                    "tags": ["DomainTools", "whois", "registrant domain count"],
                }
            )
        if self.helper.safe_path(results, ["server", "other_domains"]) and self.helper.safe_path_result != "":
            self.helper.append_unique_payload(
                {
                    "types": ["text"],
                    "categories": ["External analysis"],
                    "values": {"co-located domain count": "IP is shared with {count} other domains".format(count=self.helper.safe_path_result)},
                    "comment": "co-located domain count from DomainTools",
                    "tags": ["DomainTools", "co-located domain count"],
                }
            )
        if self.helper.safe_path(results, ["name_servers"]):
            for ns in self.helper.safe_path_result:
                if ns != "":
                    self.helper.append_unique_payload(
                        {
                            "types": ["hostname"],
                            "values": {"name server": ns["server"]},
                            "comment": "name server from DomainTools",
                            "tags": ["DomainTools", "whois", "nameserver"],
                        }
                    )
        if self.helper.safe_path(results, ["registration", "created"]) and self.helper.safe_path_result != "":
            self.helper.append_unique_payload(
                {
                    "types": ["whois-creation-date"],
                    "values": {"creation date": self.helper.safe_path_result},
                    "comment": "creation date from DomainTools",
                    "tags": ["DomainTools", "whois", "creation date"],
                }
            )
        if self.helper.safe_path(results, ["registration", "registrar"]) and self.helper.safe_path_result != "":
            self.helper.append_unique_payload(
                {
                    "types": ["whois-registrar"],
                    "values": {"registrar": self.helper.safe_path_result},
                    "comment": "registrar from DomainTools",
                    "tags": ["DomainTools", "whois", "registrar"],
                }
            )
        return True

    def risk(self, query, query_type):
        if "risk" not in self.svc_enabled or self.svc_enabled["risk"] <= 0:
            if self.plugin.debug:
                self.plugin.log.debug("risk: service disabled or over monthly limit")

        if self.plugin.module["name"] == "DomainTools-Historic":
            return True
        if self.plugin.module["name"] == "DomainTools-Iris-Investigate":
            return True
        if self.plugin.module["name"] == "DomainTools-Iris-Enrich":
            return True
        if self.plugin.module["name"] == "DomainTools-Iris-Pivot":
            return True

        tldex = tldextract.extract(query.replace("\\/", "/"))
        q = tldex.top_domain_under_public_suffix
        if q == "":
            return True

        method = self.api._results("risk", "/v1/risk", domain=q)
        results = method.data()
        results = results["response"]
        if method._status != 200:
            return True
        if results.get("error"):
            self.plugin.errors["error"] = results["error"]["message"]
            return False

        self.helper.simple_parse("risk_score", results)
        # self.helper.simple_parse(_what='components', _from_where=pw, _parent='risk score')
        if self.helper.safe_get(results, "components"):
            reasons = list()
            for item in self.helper.safe_get_result:
                for dict_key in item:
                    reasons.append("{0}: {1}".format(dict_key, item[dict_key]))
                if len(reasons) > 0:
                    self.helper.append_unique_payload(
                        {
                            "types": ["text"],
                            "categories": ["External analysis"],
                            "values": {"risk score reason": ", ".join(reasons)},
                            "comment": "risk score reason from DomainTools",
                            "tags": ["DomainTools", "risk score reason"],
                        }
                    )
        return True

    def reverse_ip(self, query, query_type):
        if "reverse-ip" not in self.svc_enabled or self.svc_enabled["reverse-ip"] <= 0:
            if self.plugin.debug:
                self.plugin.log.debug("reverse-ip: service disabled or over monthly limit")

        if self.plugin.module["name"] == "DomainTools-Historic":
            return True
        if self.plugin.module["name"] == "DomainTools-Iris-Investigate":
            return True
        if self.plugin.module["name"] == "DomainTools-Iris-Enrich":
            return True
        if self.plugin.module["name"] == "DomainTools-Iris-Pivot":
            return True

        tldex = tldextract.extract(query.replace("\\/", "/"))
        q = tldex.top_domain_under_public_suffix
        if q == "":
            return True

        if self.helper.module_has_type("expansion"):
            method = self.api.reverse_ip(query)
        else:
            method = self.api.reverse_ip(query, limit=0)
            results = method.data()
            results = results["response"]

        if method._status != 200:
            return True
        if results.get("error"):
            self.plugin.errors["error"] = results["error"]["message"]
            return False

        if self.helper.safe_get(results, "ip_addresses"):
            if type(self.helper.safe_get_result) is list:
                for item in self.helper.safe_get_result:
                    if item["domain_count"] != "":
                        self.helper.append_unique_payload(
                            {
                                "types": ["text"],
                                "categories": ["External analysis"],
                                "values": {
                                    "co-located domain count": "{0} is shared with {count} other domains".format(q, item["domain_count"])
                                },
                                "comment": "co-located domain count from DomainTools",
                                "tags": ["DomainTools", "co-located domain count"],
                            }
                        )

                    if self.helper.module_has_type("expansion"):
                        limit = int(self.plugin.config.get("results_limit"))
                        for d in item["domain_names"]:
                            if limit == 0:
                                break
                            limit = limit - 1
                            if d != "":
                                self.helper.append_unique_payload(
                                    {
                                        "types": ["domain"],
                                        "values": {"reverse ip domain": d},
                                        "comment": "reverse ip domain from DomainTools",
                                        "tags": ["DomainTools", "reverse ip domain"],
                                    }
                                )
                        if item["ip_address"] != query and item["ip_address"] != "":
                            self.helper.append_unique_payload(
                                {
                                    "types": ["ip-src", "ip-dst"],
                                    "values": {"reverse ip": item["ip_address"]},
                                    "comment": "reverse ip from DomainTools",
                                    "tags": ["DomainTools", "reverse ip"],
                                }
                            )
            else:
                if self.helper.safe_get_result["domain_count"] != "":
                    self.helper.append_unique_payload(
                        {
                            "types": ["text"],
                            "categories": ["External analysis"],
                            "values": {
                                "co-located domain count": "{0} is shared with {count} other domains".format(
                                    q, count=self.helper.safe_get_result["domain_count"]
                                )
                            },
                            "comment": "co-located domain count from DomainTools",
                            "tags": ["DomainTools", "co-located domain count"],
                        }
                    )
                if self.helper.module_has_type("expansion"):
                    limit = int(self.plugin.config.get("results_limit"))
                    for d in self.helper.safe_get_result["domain_names"]:
                        if limit == 0:
                            break
                        limit = limit - 1
                        if d != "":
                            self.helper.append_unique_payload(
                                {
                                    "types": ["domain"],
                                    "values": {"reverse ip domain": d},
                                    "comment": "reverse ip domain from DomainTools",
                                    "tags": ["DomainTools", "reverse ip domain"],
                                }
                            )
        return True

    def reverse_whois(self, query, query_type):
        if "reverse-whois" not in self.svc_enabled or self.svc_enabled["reverse-whois"] <= 0:
            if self.plugin.debug:
                self.plugin.log.debug("reverse-whois: service disabled or over monthly limit")

        if self.plugin.module["name"] == "DomainTools-Historic":
            return True
        if self.plugin.module["name"] == "DomainTools-Iris-Investigate":
            return True
        if self.plugin.module["name"] == "DomainTools-Iris-Enrich":
            return True
        if self.plugin.module["name"] == "DomainTools-Iris-Pivot":
            return True

        if self.helper.module_has_type("expansion"):
            method = self.api.reverse_whois(query, mode="purchase")
        else:
            method = self.api.reverse_whois(query, mode="quote")
        results = method.data()
        results = results["response"]
        if method._status != 200:
            return True
        if results.get("error"):
            self.plugin.errors["error"] = results["error"]["message"]
            return False

        if self.helper.safe_get(results, "domains"):
            for domain in self.helper.safe_get_result:
                if domain != "":
                    self.helper.append_unique_payload(
                        {
                            "types": ["domain"],
                            "values": {"reverse whois domain": domain},
                            "comment": "reverse whois domain from DomainTools",
                            "tags": ["DomainTools", "reverse whois domain"],
                        }
                    )
        if self.helper.safe_get(results, "domain_count"):
            if "current" in self.helper.safe_get_result:
                self.helper.append_unique_payload(
                    {
                        "types": ["text"],
                        "categories": ["External analysis"],
                        "values": {"current domain count": self.helper.safe_get_result["current"]},
                        "comment": "domain count current from DomainTools",
                        "tags": ["DomainTools", "reverse whois domain"],
                    }
                )
            if "historic" in self.helper.safe_get_result:
                self.helper.append_unique_payload(
                    {
                        "types": ["text"],
                        "categories": ["External analysis"],
                        "values": {"historic domain count": self.helper.safe_get_result["historic"]},
                        "comment": "historic domain count from DomainTools",
                        "tags": ["DomainTools", "reverse whois"],
                    }
                )
        return True

    def host_domains(self, query, query_type):
        if "reverse-ip" not in self.svc_enabled or self.svc_enabled["reverse-ip"] <= 0:
            if self.plugin.debug:
                self.plugin.log.debug("reverse-ip: service disabled or over monthly limit")

        if self.plugin.module["name"] == "DomainTools-Historic":
            return True
        if self.plugin.module["name"] == "DomainTools-Iris-Investigate":
            return True
        if self.plugin.module["name"] == "DomainTools-Iris-Enrich":
            return True
        if self.plugin.module["name"] == "DomainTools-Iris-Pivot":
            return True

        if self.helper.module_has_type("expansion"):
            method = self.api.host_domains(query)
        else:
            method = self.api.host_domains(query, limit=0)
        results = method.data()
        results = results["response"]
        if method._status != 200:
            return True
        if results.get("error"):
            self.plugin.errors["error"] = results["error"]["message"]
            return False

        if self.helper.safe_get(results, "ip_addresses"):
            if self.helper.safe_get_result["ip_address"] != "":
                self.helper.append_unique_payload(
                    {
                        "types": ["text"],
                        "categories": ["External analysis"],
                        "values": {"co-located domain count": self.helper.safe_get_result["domain_count"]},
                        "comment": "co-located domain count from DomainTools",
                        "tags": ["DomainTools", "co-located domain count"],
                    }
                )

                if self.helper.module_has_type("expansion"):
                    limit = int(self.plugin.config.get("results_limit"))
                    for d in self.helper.safe_get_result["domain_names"]:
                        if limit == 0:
                            break
                        limit = limit - 1
                        if d != "":
                            self.helper.append_unique_payload(
                                {
                                    "types": ["domain"],
                                    "values": {"co-located domain": d},
                                    "comment": "co-located domain from DomainTools",
                                    "tags": ["DomainTools", "co-located domain"],
                                }
                            )
        return True

    def hosting_history(self, query, query_type):
        if "hosting-history" not in self.svc_enabled or self.svc_enabled["hosting-history"] <= 0:
            if self.plugin.debug:
                self.plugin.log.debug("hosting-history: service disabled or over monthly limit")

        if self.plugin.module["name"] != "DomainTools-Historic":
            return True

        tldex = tldextract.extract(query.replace("\\/", "/"))
        q = tldex.top_domain_under_public_suffix
        if q == "":
            return True

        method = self.api.hosting_history(q)
        results = method.data()
        results = results["response"]
        if method._status != 200:
            return
        if results.get("error"):
            self.plugin.errors["error"] = results["error"]["message"]
            return False

        if self.helper.safe_get(results, "ip_history"):
            for item in self.helper.safe_get_result:
                if item["pre_ip"] is not None and item["pre_ip"] != "":
                    self.helper.append_unique_payload(
                        {
                            "types": ["ip-src", "ip-dst"],
                            "values": {"ip": item["pre_ip"]},
                            "comment": "record date: {0}".format(item["actiondate"]),
                            "tags": [
                                "DomainTools",
                                "hosting history",
                                "whois",
                                "ip",
                                "historic",
                            ],
                        }
                    )
                if item["post_ip"] is not None and item["post_ip"] != "":
                    self.helper.append_unique_payload(
                        {
                            "types": ["ip-src", "ip-dst"],
                            "values": {"ip": item["post_ip"]},
                            "comment": "record date: {0}".format(item["actiondate"]),
                            "tags": [
                                "DomainTools",
                                "hosting history",
                                "whois",
                                "ip",
                                "historic",
                            ],
                        }
                    )

        if self.helper.safe_get(results, "nameserver_history"):
            for item in self.helper.safe_get_result:
                if item["pre_mns"] is not None and item["pre_mns"] != "":
                    self.helper.append_unique_payload(
                        {
                            "types": ["hostname"],
                            "values": {"nameserver": item["pre_mns"]},
                            "comment": "record date: {0}".format(item["actiondate"]),
                            "tags": [
                                "DomainTools",
                                "hosting history",
                                "whois",
                                "nameserver",
                                "historic",
                            ],
                        }
                    )
                if item["post_mns"] is not None and item["post_mns"] != "":
                    self.helper.append_unique_payload(
                        {
                            "types": ["hostname"],
                            "values": {"nameserver": item["post_mns"]},
                            "comment": "record date: {0}".format(item["actiondate"]),
                            "tags": [
                                "DomainTools",
                                "hosting history",
                                "whois",
                                "nameserver",
                                "historic",
                            ],
                        }
                    )

        if self.helper.safe_get(results, "registrar_history"):
            for item in self.helper.safe_get_result:
                if item["registrar"] is not None and item["registrar"] != "":
                    self.helper.append_unique_payload(
                        {
                            "types": ["whois-registrar"],
                            "values": {"registrar": item["registrar"]},
                            "comment": "record date: {0}".format(item["date_lastchecked"]),
                            "tags": [
                                "DomainTools",
                                "hosting history",
                                "registrar",
                                "historic",
                            ],
                        }
                    )
        return True

    def whois_history(self, query, query_type):
        if "whois-history" not in self.svc_enabled or self.svc_enabled["whois-history"] <= 0:
            if self.plugin.debug:
                self.plugin.log.debug("whois-history: service disabled or over monthly limit")

        if self.plugin.module["name"] != "DomainTools-Historic":
            return True

        tldex = tldextract.extract(query.replace("\\/", "/"))
        q = tldex.top_domain_under_public_suffix
        if q == "":
            return True

        method = self.api.whois_history(q)
        results = method.data()
        results = results["response"]
        if method._status != 200:
            return True
        if results.get("error"):
            self.plugin.errors["error"] = results["error"]["message"]
            return False

        if self.helper.safe_get(results, "history"):
            for item in self.helper.safe_get_result:
                matches = re.findall(
                    r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)",
                    item["whois"]["record"],
                )
                for match in list(set(matches)):
                    if match != "":
                        self.helper.append_unique_payload(
                            {
                                "types": ["whois-registrant-email"],
                                "values": {"email": match},
                                "comment": "record date: {0}".format(item["date"]),
                                "tags": ["DomainTools", "whois history"],
                            }
                        )
        return True

    def iris_hover(self, query, query_type):
        module_name = self.plugin.module["name"]
        if module_name not in [
            "DomainTools-Iris-Enrich",
            "DomainTools-Iris-Investigate",
        ]:
            return True

        tldex = tldextract.extract(query.replace("\\/", "/"))
        q = tldex.top_domain_under_public_suffix
        if q == "":
            self.plugin.log.debug("q is empty")
            return True

        if module_name == "DomainTools-Iris-Investigate":
            service = "iris-investigate"
            method = self.api.iris_investigate(q)
        else:
            service = "iris-enrich"
            method = self.api.iris_enrich(q)

        if service not in self.svc_enabled or self.svc_enabled[service] <= 0:
            if self.plugin.debug:
                self.plugin.log.debug("{0}: service disabled or over monthly limit".format(service))

        results = method.data()
        results = results["response"]

        if method._status != 200:
            return
        if results.get("error"):
            self.plugin.errors["error"] = results["error"]["message"]
            return False

        if not self.helper.safe_get(results, "results"):
            self.plugin.errors["error"] = "No results found."
            return True

        result = self.helper.safe_get_result.pop()

        if self.helper.safe_path(result, ["create_date", "value"]) and self.helper.safe_path_result != "":
            create_date = self.helper.safe_path_result
            age = self.helper.calculate_age(create_date)
            self.helper.append_unique_payload(
                {
                    "types": ["datetime"],
                    "categories": ["External analysis"],
                    "values": {"Create Date": "{0} 00:00:00".format(create_date)},
                    "comment": "Create Date from DomainTools",
                    "tags": ["DomainTools", "Create Date"],
                }
            )
            self.helper.append_unique_payload(
                {
                    "types": ["text"],
                    "categories": ["External analysis"],
                    "values": {"Domain Age": "{0} created {1} ago".format(q, age)},
                    "comment": "Domain Age from DomainTools",
                    "tags": ["DomainTools", "Domain Age"],
                }
            )

        if self.helper.safe_path(result, ["expiration_date", "value"]) and self.helper.safe_path_result != "":
            expiration_date = self.helper.safe_path_result
            self.helper.append_unique_payload(
                {
                    "types": ["datetime"],
                    "categories": ["External analysis"],
                    "values": {"Expiration Date": "{0} 00:00:00".format(expiration_date)},
                    "comment": "Expiration Date from DomainTools",
                    "tags": ["DomainTools", "Expiration Date"],
                }
            )

        if self.helper.safe_get(result, "registrant_contact"):
            registrant_contact = self.helper.safe_get_result
            self.helper.simple_parse(
                "value",
                registrant_contact["name"],
                ["text"],
                "registrant name from DomainTools",
                ["DomainTools", "Iris"],
                "Registrant Name",
            )
            for email in registrant_contact["email"]:
                self.helper.simple_parse(
                    "value",
                    email,
                    ["whois-registrant-email"],
                    "Registrant Email from DomainTools",
                    ["DomainTools", "Iris"],
                    "Registrant Email",
                )
        if self.helper.safe_get(result, "registrar"):
            self.helper.simple_parse(
                "value",
                self.helper.safe_get_result,
                ["text"],
                "Registrar from DomainTools",
                ["DomainTools", "Iris"],
                "Registrar Name",
            )

        if self.helper.safe_get(result, "registrant_org"):
            self.helper.simple_parse(
                "registrant_org",
                result,
                ["text"],
                "Registrant Organization from DomainTools",
                ["DomainTools", "Iris"],
                "Registrant Organization",
            )

        if self.helper.safe_get(result, "domain_risk"):
            risk = self.helper.safe_get_result
            self.helper.simple_parse(
                "risk_score",
                risk,
                ["text"],
                "Risk from DomainTools",
                ["DomainTools", "Iris"],
                "Risk Score",
            )

            risk_score_threats = set()
            risk_score_evidence = set()
            for component in risk["components"]:
                self.helper.append_unique_payload(
                    {
                        "types": ["text"],
                        "categories": ["External analysis"],
                        "values": {"Risk Score Component": f"{component['name']} ({component['risk_score']})"},
                        "comment": "Risk Score Component from DomainTools",
                        "tags": ["DomainTools", "Iris"],
                    }
                )
                threats = component.get("threats")
                if threats:
                    risk_score_threats.update(threats)

                evidence = component.get("evidence")
                if evidence:
                    risk_score_evidence.update(evidence)

            if risk_score_threats:
                self.helper.append_unique_payload(
                    {
                        "types": ["text"],
                        "categories": ["External analysis"],
                        "values": {"Risk Score Component Threats": ", ".join(sorted(risk_score_threats))},
                        "comment": "Risk Score Threats from DomainTools",
                        "tags": ["DomainTools", "Iris"],
                    }
                )

            if risk_score_evidence:
                self.helper.append_unique_payload(
                    {
                        "types": ["text"],
                        "categories": ["External analysis"],
                        "values": {"Risk Score Component Evidence": ", ".join(sorted(risk_score_evidence))},
                        "comment": "Risk Score Evidence from DomainTools",
                        "tags": ["DomainTools", "Iris"],
                    }
                )

        if self.helper.safe_get(result, "ssl_info"):
            for ssl in self.helper.safe_get_result:
                self.helper.simple_parse(
                    "value",
                    ssl["organization"],
                    ["text"],
                    "SSL Org from DomainTools",
                    ["DomainTools", "Iris"],
                    "SSL Org",
                )

        if self.helper.safe_get(result, "active"):
            is_active = "True" if self.helper.safe_get_result else "False"
            self.helper.append_unique_payload(
                {
                    "types": ["text"],
                    "values": {"Active": is_active},
                    "comment": "Active from DomainTools",
                    "tags": ["DomainTools", "Iris"],
                }
            )

        self.helper.simple_parse(
            "popularity_rank",
            result,
            ["text"],
            "Rank from DomainTools",
            ["DomainTools", "Iris"],
            "Rank",
        )

        if module_name == "DomainTools-Iris-Investigate":
            # Iris-Investigate specific data
            if self.helper.safe_get(result, "ip"):
                for ip in self.helper.safe_get_result:
                    self.helper.simple_parse(
                        "value",
                        ip["address"],
                        ["ip-dst"],
                        "IP address from DomainTools",
                        ["DomainTools", "Iris"],
                        "IP Address",
                    )
                    self.helper.simple_parse(
                        "value",
                        ip["country_code"],
                        ["text"],
                        "country code from DomainTools",
                        ["DomainTools", "Iris"],
                        "IP Country Code",
                    )
                    self.helper.simple_parse(
                        "value",
                        ip["isp"],
                        ["text"],
                        "ISP from DomainTools",
                        ["DomainTools", "Iris"],
                        "IP ISP",
                    )

            if self.helper.safe_get(result, "name_server"):
                for index, name_server in zip(range(len(self.helper.safe_get_result)), self.helper.safe_get_result):
                    self.helper.simple_parse(
                        "value",
                        name_server["host"],
                        ["hostname"],
                        "Name Server from DomainTools",
                        ["DomainTools", "Iris"],
                        "Name Server",
                    )

            if self.helper.safe_get(result, "mx"):
                for index, name_server in zip(range(2), self.helper.safe_get_result):
                    self.helper.simple_parse(
                        "value",
                        name_server["host"],
                        ["text"],
                        "Mail Server from DomainTools",
                        ["DomainTools", "Iris"],
                        "Mail Server Host",
                    )

            if self.helper.safe_get(result, "create_date"):
                self.helper.extract_nested_value(self.helper.safe_get_result, "create date")

        # For Iris-Investigate Guided Pivots, we get the count only
        # For Iris-Enrich we get the values only
        if self.helper.safe_get(result, "technical_contact"):
            self.helper.get_count_or_value(self.helper.safe_get_result, "technical contact")
        if self.helper.safe_get(result, "admin_contact"):
            self.helper.get_count_or_value(self.helper.safe_get_result, "admin contact")
        if self.helper.safe_get(result, "billing_contact"):
            self.helper.get_count_or_value(self.helper.safe_get_result, "billing contact")
        if self.helper.safe_get(result, "redirect_domain"):
            self.helper.extract_nested_value(self.helper.safe_get_result, "redirect domain")
        if self.helper.safe_get(result, "registrar"):
            self.helper.extract_nested_value(self.helper.safe_get_result, "registrar")
        if self.helper.safe_get(result, "google_analytics"):
            self.helper.extract_nested_value(self.helper.safe_get_result, "google analytics")
        if self.helper.safe_get(result, "registrant_contact"):
            self.helper.get_count_or_value(self.helper.safe_get_result, "registrant contact")
        if self.helper.safe_get(result, "registrant_org"):
            self.helper.get_count_or_value(self.helper.safe_get_result, "registrant organization")
        if self.helper.safe_get(result, "registrant_name"):
            self.helper.get_count_or_value(self.helper.safe_get_result, "registrant name")
        if self.helper.safe_get(result, "ip"):
            for ip in self.helper.safe_get_result:
                self.helper.get_count_or_value(ip, "ip")
        if self.helper.safe_get(result, "ssl_info"):
            for ssl in self.helper.safe_get_result:
                self.helper.get_count_or_value(ssl, "ssl")
        if self.helper.safe_get(result, "mx"):
            for mx in self.helper.safe_get_result:
                self.helper.get_count_or_value(mx, "mx")
        if self.helper.safe_get(result, "email_domain"):
            for email_domain in self.helper.safe_get_result:
                self.helper.extract_nested_value(email_domain, "email domain")

        if self.helper.safe_get(result, "name_server"):
            for email_domain in self.helper.safe_get_result:
                self.helper.get_count_or_value(email_domain, "name server")

        return True

    def iris_pivot(self, query, query_type):
        if "iris-investigate" not in self.svc_enabled or self.svc_enabled["iris-investigate"] <= 0:
            if self.plugin.debug:
                self.plugin.log.debug("iris-investigate: service disabled or over monthly limit")

        if self.plugin.module["name"] != "DomainTools-Iris-Pivot":
            return True

        if query_type == "domain":
            self.iris_pivot_domain(query)
        elif query_type in PIVOT_MAP:
            self.iris_pivot_other(query, query_type)

        return True

    def iris_pivot_other(self, query, query_type):
        pivot_type = PIVOT_MAP.get(query_type)
        arguments = {pivot_type: query}
        method = self.api.iris_investigate(**arguments)

        results = method.data()
        results = results["response"]

        if method._status != 200:
            return
        if results.get("error"):
            self.plugin.errors["error"] = results["error"]["message"]
            return False

        if not self.helper.safe_get(results, "results"):
            error_message = "No results found."

            if query_type == "hostname":
                error_message += " Try searching by domain."

            self.plugin.errors["error"] = error_message

            return True

        limit = int(self.plugin.config.get("results_limit"))
        for result in self.helper.safe_get_result[0:limit]:
            self.helper.simple_parse(
                "domain",
                result,
                ["domain"],
                "Domain from DomainTools Iris",
                ["DomainTools", "Iris"],
                "Domain",
            )

    def iris_pivot_domain(self, query):
        tldex = tldextract.extract(query.replace("\\/", "/"))
        q = tldex.top_domain_under_public_suffix
        if q == "":
            self.plugin.log.debug("q is empty")
            return True

        method = self.api.iris_investigate(q)
        results = method.data()
        results = results["response"]

        if method._status != 200:
            return
        if results.get("error"):
            self.plugin.errors["error"] = results["error"]["message"]
            return False

        if not self.helper.safe_get(results, "results"):
            self.plugin.errors["error"] = "No results found."
            return True

        result = self.helper.safe_get_result.pop()

        self.helper.simple_parse(
            "popularity_rank",
            result,
            ["text"],
            "Rank from DomainTools",
            ["DomainTools", "Iris"],
            "Rank",
        )
        self.helper.simple_parse(
            "spf_info",
            result,
            ["text"],
            "SPF Info from DomainTools",
            ["DomainTools", "Iris"],
            "SPF",
        )
        self.helper.simple_parse(
            "website_response",
            result,
            ["text"],
            "Website Response from DomainTools",
            ["DomainTools", "Iris"],
            "Website Response",
        )

        if self.helper.safe_get(result, "create_date"):
            self.helper.iris_add(
                self.helper.safe_get_result,
                ["whois-creation-date"],
                "Create Date",
                categories=["Attribution"],
            )
        if self.helper.safe_get(result, "expiration_date"):
            self.helper.iris_add(self.helper.safe_get_result, ["text"], "Expiration Date")
        if self.helper.safe_get(result, "redirect_domain"):
            self.helper.iris_add(self.helper.safe_get_result, ["domain"], "Redirect Domain")
        if self.helper.safe_get(result, "registrar"):
            self.helper.iris_add(
                self.helper.safe_get_result,
                ["whois-registrar"],
                "Registrar",
                categories=["Attribution"],
            )
        if self.helper.safe_get(result, "adsense"):
            self.helper.iris_add(self.helper.safe_get_result, ["text"], "Adsense")

        if self.helper.safe_get(result, "technical_contact"):
            self.helper.iris_address(self.helper.safe_get_result, "Technical Contact")
        if self.helper.safe_get(result, "registrant_contact"):
            self.helper.iris_address(self.helper.safe_get_result, "Registrant Contact")
        if self.helper.safe_get(result, "admin_contact"):
            self.helper.iris_address(self.helper.safe_get_result, "Admin Contact")
        if self.helper.safe_get(result, "billing_contact"):
            self.helper.iris_address(self.helper.safe_get_result, "Billing Contact")

        if self.helper.safe_get(result, "ip"):
            ips = self.helper.safe_get_result
            for ip in ips:
                self.helper.iris_add(ip["address"], ["ip-dst"], "IP Address")
                self.helper.iris_add(ip["country_code"], ["text"], "Country Code")
                self.helper.iris_add(ip["isp"], ["text"], "IP ISP")

                for asn in ip["asn"]:
                    self.helper.iris_add(asn, ["text"], "IP ASN")

        if self.helper.safe_get(result, "ssl_info"):
            for ssl in self.helper.safe_get_result:
                self.helper.iris_add(ssl["organization"], ["text"], "SSL Org")
                self.helper.iris_add(ssl["subject"], ["text"], "SSL Subject")
                self.helper.iris_add(ssl["hash"], ["x509-fingerprint-sha1"], "SSL Hash")

                for email in ssl["email"]:
                    self.helper.iris_add(
                        email,
                        ["email-dst"],
                        "SSL Email",
                        categories=["Network activity"],
                    )

        if self.helper.safe_get(result, "name_server"):
            for name_server in self.helper.safe_get_result:
                self.helper.iris_add(name_server["host"], ["hostname"], "Name Server Host")
                self.helper.iris_add(name_server["domain"], ["domain"], "Name Server Domain")

                for ip in name_server["ip"]:
                    self.helper.iris_add(ip, ["ip-src"], "Name Server IP")

        if self.helper.safe_get(result, "mx"):
            for mx in self.helper.safe_get_result:
                self.helper.iris_add(mx["host"], ["hostname"], "Mail Server Host")
                self.helper.iris_add(mx["domain"], ["domain"], "Mail Server Domain")

                for ip in mx["ip"]:
                    self.helper.iris_add(ip, ["ip-src"], "Mail Server IP")

        if self.helper.safe_get(result, "soa_email"):
            for soa in self.helper.safe_get_result:
                self.helper.iris_add(soa, ["email-dst"], "SOA email", categories=["Network activity"])

        if self.helper.safe_get(result, "additional_whois_email"):
            for email in self.helper.safe_get_result:
                self.helper.iris_add(
                    email,
                    ["whois-registrant-email"],
                    "Whois Email",
                    categories=["Attribution"],
                )

        if self.helper.safe_get(result, "domain_risk"):
            risk = self.helper.safe_get_result
            self.helper.simple_parse(
                "risk_score",
                risk,
                ["text"],
                "Risk Score from DomainTools",
                ["DomainTools", "Iris"],
                "Risk Score",
            )
            for index, component in enumerate(risk["components"]):
                self.helper.append_unique_payload(
                    {
                        "types": ["text"],
                        "categories": ["External analysis"],
                        "values": {
                            "{0} Risk Component".format(component["name"]): "{0}".format(component["risk_score"], component["risk_score"])
                        },
                        "comment": "{0} Risk Component from DomainTools".format(component["name"]),
                        "tags": ["DomainTools", "Iris"],
                    }
                )

    def iris_import(self, query, query_type):
        if "iris-import" not in self.svc_enabled or self.svc_enabled["iris-import"] <= 0:
            if self.plugin.debug:
                self.plugin.log.debug("iris-import: service disabled or over monthly limit")

        if self.plugin.module["name"] != "DomainTools-Iris-Import":
            return True

        # This is used to remove the first two characters: `b'`
        STRINGIFIED_BASE64_SEARCH_HASH_START_INDEX = 2
        # This is used to remove the last character: `'`
        STRINGIFIED_BASE64_SEARCH_HASH_END_INDEX = -1

        stringified_search_hash = (
            str(base64.b64decode(query))[STRINGIFIED_BASE64_SEARCH_HASH_START_INDEX:STRINGIFIED_BASE64_SEARCH_HASH_END_INDEX]
            if query and query != ""
            else ""
        )

        if stringified_search_hash == "":
            error_message = "Query is empty. Please input a valid search hash."
            self.plugin.log.debug(error_message)
            self.plugin.errors["error"] = error_message
            return True

        method = self.api.iris_investigate(search_hash=stringified_search_hash)

        results = method.data()
        results = results["response"]

        if method._status != 200:
            return
        if results.get("error"):
            self.plugin.errors["error"] = results["error"]["message"]
            return False

        if not self.helper.safe_get(results, "results"):
            self.plugin.errors["error"] = "No results found."
            return True

        limit = int(self.plugin.config.get("results_limit"))
        for result in self.helper.safe_get_result[0:limit]:
            self.helper.simple_parse(
                "domain",
                result,
                ["domain"],
                "Domain from DomainTools Iris",
                ["DomainTools", "Iris"],
                "Domain",
            )

        return True

    def iris_detect(self, query, query_type):
        if "iris-detect" not in self.svc_enabled or self.svc_enabled["iris-detect"] <= 0:
            if self.plugin.debug:
                self.plugin.log.debug("iris-detect: service disabled or over monthly limit")

        if self.plugin.module["name"] != "DomainTools-Iris-Detect":
            return True

        api_endpoint = self.plugin.config.get("api_endpoint")
        monitor_id = None if self.plugin.config.get("monitor_id") == "" else self.plugin.config.get("monitor_id")
        discovered_date = self.plugin.config.get("discovered_date")
        changed_since = self.plugin.config.get("changed_since")
        escalated_since = self.plugin.config.get("escalated_since")
        risk_score_ranges = self.plugin.config.get("risk_score_ranges")
        escalation_types = self.plugin.config.get("escalation_types")
        tag_domains_as_blocked = self.plugin.config.get("tag_domains_as_blocked")
        preview = self.plugin.config.get("test_mode")
        include_domain_data = self.plugin.config.get("include_domain_data")
        none_or_empty = ("None", "")
        incorrect_date_format_error = "Incorrect data format, should be YYYY-MM-DD or YYYY-MM-DDThh:mm:ss+00:00"

        if discovered_date in none_or_empty:
            discovered_date = None
        else:
            if not self.helper.is_valid_datetime(discovered_date):
                self.plugin.log.debug(incorrect_date_format_error)
                self.plugin.errors["error"] = incorrect_date_format_error
                return False

        if changed_since in none_or_empty:
            changed_since = None
        else:
            if not self.helper.is_valid_datetime(changed_since):
                self.plugin.log.debug(incorrect_date_format_error)
                self.plugin.errors["error"] = incorrect_date_format_error
                return False

        if escalated_since in none_or_empty:
            escalated_since = None
        else:
            if not self.helper.is_valid_datetime(escalated_since):
                self.plugin.log.debug(incorrect_date_format_error)
                self.plugin.errors["error"] = incorrect_date_format_error
                return False

        risk_score_ranges = RISK_SCORE_RANGES_MAP[risk_score_ranges]
        escalation_types = ESCALATION_TYPES_MAP[escalation_types]
        preview = True if (preview == "1") else False
        include_domain_data = True if (include_domain_data == "1") else False

        try:
            if api_endpoint == "1":
                results = self.api.iris_detect_watched_domains(
                    monitor_id=monitor_id,
                    changed_since=changed_since,
                    escalated_since=escalated_since,
                    risk_score_ranges=risk_score_ranges,
                    escalation_types=escalation_types,
                    preview=preview,
                    include_domain_data=include_domain_data,
                )
            else:
                results = self.api.iris_detect_new_domains(
                    monitor_id=monitor_id,
                    discovered_since=discovered_date,
                    risk_score_ranges=risk_score_ranges,
                    preview=preview,
                    include_domain_data=include_domain_data,
                )
        except Exception as error:
            self.plugin.log.debug(f"Failed to retrieve data due to : {str(error)}")
            self.plugin.errors["error"] = str(error)
            return False

        domain_id_list = []
        tag_td = ["DomainTools", "Iris"]
        results = results.get("watchlist_domains")

        for watchlisted_domain in results:
            self.plugin.payload.append(
                {
                    "categories": ["External analysis"],
                    "type": "domain",
                    "values": watchlisted_domain["domain"],
                    "tags": tag_td,
                }
            )
            domain_id_list.append(watchlisted_domain["id"])

            for name_server in watchlisted_domain.get("name_server", []):
                self.plugin.payload.append(
                    {
                        "categories": ["External analysis"],
                        "type": "domain",
                        "values": name_server["host"],
                        "tags": tag_td + ["Name Server"],
                        "comment": "Name Server " + watchlisted_domain["domain"],
                    }
                )

            for mx in watchlisted_domain.get("mx", []):
                self.plugin.payload.append(
                    {
                        "categories": ["External analysis"],
                        "type": "domain",
                        "values": mx["host"],
                        "tags": tag_td + ["Mail Host"],
                        "comment": "Mail Host " + watchlisted_domain["domain"],
                    }
                )

            for ip in watchlisted_domain.get("ip", []):
                self.plugin.payload.append(
                    {
                        "categories": ["External analysis"],
                        "type": "ip-src",
                        "values": ip["ip"],
                        "tags": tag_td + ["IP"],
                        "comment": "IP " + watchlisted_domain["domain"],
                    }
                )

        if not self.plugin.payload:
            self.plugin.errors["error"] = "No results found."
            return False

        # Perform domains marking for 'new' api_endpoint
        if tag_domains_as_blocked == "1" and api_endpoint == "0":
            try:
                result = self.api.iris_detect_escalate_domains(domain_id_list, "blocked")
                if result.status == 200:
                    self.plugin.log.debug(f"Done blocking domains: {domain_id_list}")
                else:
                    # For some unknown reason, this block of code is needed to catch the Exception below
                    self.plugin.log.debug("Blocking domain(s) unsuccessful.")
            except Exception as error:
                error_message = f"Failed to block domain(s) due to : {error.reason['error']['message']}"
                self.plugin.log.debug(error_message)
                self.plugin.errors["error"] = error_message
                return False

        return True
