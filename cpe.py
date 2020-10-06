#!/bin/python

import re

from packaging import version


# Parse CPE stuff
# Stolen from vulnix
# Thanks<3
def get_cpes(data):
    cpes = []
    nodes = data["configurations"]["nodes"]
    R_UNQUOTE = re.compile(r'(\\:)+')
    for node in nodes:
        if not node.get("cpe_match"):
            continue
        for expr in node["cpe_match"]:
            if expr.get('vulnerable') is not True:
                continue
            cpe23Uri = R_UNQUOTE.sub('-', expr['cpe23Uri'])
            (cpe, cpevers, typ, vendor, product, vers, rev, _) = \
                cpe23Uri.split(':', 7)
            if cpe != 'cpe' or cpevers != '2.3':
                continue
            e = {"package": product,
                 "version": []}
            version = []
            if vers and vers != '*' and vers != '-':
                if rev and rev != '*' and rev != '-':
                    vers = vers + '-' + rev
                # Exact match: Change self.version to a string with a single
                # version. Doing this, future attempts to apppend() will fail.
                version.append(str(vers))
            if 'versionStartIncluding' in expr:
                version.append('>=' + expr['versionStartIncluding'])
            if 'versionStartExcluding' in expr:
                version.append('>' + expr['versionStartExcluding'])
            if 'versionEndIncluding' in expr:
                version.append('<=' + expr['versionEndIncluding'])
            if 'versionEndExcluding' in expr:
                version.append('<' + expr['versionEndExcluding'])
            if version:
                e = {"package": product,
                    "version": version}
                cpes.append(e)

                # The logic here is to that some vendors append suffixes to
                # their product. linux the vendor adds CVEs to linux_kernel
                if vendor in product and vendor != product:
                    e["package"] = vendor
                    cpes.append(e)
    return cpes


def in_range(pvers, spec):
    pvers = pvers.split(":")[-1].split("-")[0]
    pvers = pvers.replace(".arch1", "").replace(".arch2", "") # Special version for linux

    # Remove illegal pkgver
    spec = spec.replace("-", "")

    #yolo
    if '>=' in spec:
        return version.parse(pvers) >= version.parse(spec[2:])
    elif '<=' in spec:
        return version.parse(pvers) <= version.parse(spec[2:])
    elif '>' in spec:
        return version.parse(pvers) > version.parse(spec[1:])
    elif '<' in spec:
        return version.parse(pvers) < version.parse(spec[1:])
    else:
        return version.parse(pvers) == version.parse(spec)
