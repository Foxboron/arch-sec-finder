#!/usr/bin/python


import requests

from cpe import get_cpes, in_range

PREFIXES = [
        "python-",
        "haskell-",
        "perl-",
        "python-",
        "python2-",
        "lib32-",
        "vim-",
        "ttf-",
]

BLACKLIST = [
        "selinux",
]


def is_valid_pkgname(packages, pkgname):
    if pkgname in BLACKLIST:
        return None
    if pkgname in packages.keys():
        return pkgname
    for prefix in PREFIXES:
        if f"{prefix}{pkgname}" in packages.keys():
            return f"{prefix}{pkgname}"

    pkgname = pkgname.lower().replace(" ", "_")
    if pkgname in packages.keys():
        return True
    for prefix in PREFIXES:
        if f"{prefix}{pkgname}" in packages.keys():
            return f"{prefix}{pkgname}"
    return None


def find_packages(packages, cves, check_tracker=False):
    avgs = {}
    for cve in cves:
        n = get_cpes(cve)
        if not n:
            continue
        for cpe in n:
            if pkgname := is_valid_pkgname(cpe["package"]):
                pkgver = packages[pkgname]
                if not all([in_range(pkgver, ver) for ver in cpe["version"]]):
                    continue
                cve_id = cve["cve"]["CVE_data_meta"]["ID"]
                if check_tracker:
                    r = requests.head(f"https://security.archlinux.org/{cve_id}")
                    if r.status_code == 200:
                        continue
                # print("----------")
                # print("Package:", pkgname)
                # print("Arch Version: ", pkgver)
                # print("Vuln version: ", cpe["version"])
                # print("CVE: ", cve_id)
                key = f"{pkgname}-{pkgver}"
                if not avgs.get(key):
                    avgs[key] = []
                avgs[key].append({
                            "pkgname": pkgname,
                            "pkgver": packages[pkgname],
                            "cve": cve["cve"]["CVE_data_meta"]["ID"],
                            "vuln_version": cpe["version"],
                            "metadata": cve,
                        })
        return avgs



def fmt_nvd_cve(nvd_data):
    description = ""
    for desc in nvd_data["metadata"]["cve"]["description"]["description_data"]:
        if desc["lang"] == "en":
            desc = desc["value"]
            break
    references = []
    for ref in nvd_data["metadata"]["cve"]["references"]["reference_data"]:
        references.append(ref["url"])
    return {
            "CVE": nvd_data['cve'],
            "pkgname": nvd_data['pkgname'],
            "pkgver": nvd_data['pkgver'],
            "severity": nvd_data['metadata']['impact']['baseMetricV3']['cvssV3']['baseSeverity'].capitalize(),
            "description": description,
            "references": references,
        }



def fmt_avg(avg):
    print(f"# {avg['cve']}")
    print(f"* Package name: {avg['pkgname']}")
    print(f"* Package version: {avg['pkgver']}")
    print(f"* Severity: {avg['severity']}")
    print()
    print("## Description")
    print(f"{avg['description']}\n")
    print("## References")
    print(f"{avg['references']}\n")


