import zlib
import json

from datetime import datetime

import requests 

from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base

from sqlalchemy_utils import JSONType
from sqlalchemy.dialects.postgresql import JSONB

from .database import Base

class NVD(Base):
    __tablename__ = 'nvd'
    cve =  Column(String(50), primary_key=True)
    data = Column(JSONType)


class WatchList(Base):
    __tablename__ = 'watchlist'
    cve =  Column(String(50), primary_key=True)
    created = Column(DateTime, nullable=False, default=datetime.utcnow)


NVD_RECENT = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz"
NVD_ALL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2020.json.gz"


def gzip_content(url):
    r = requests.get(url)
    data = zlib.decompress(r.content, 16+zlib.MAX_WBITS)
    return json.loads(data)


def get_recent_nvd_data():
    return gzip_content(NVD_RECENT)


def get_all_nvd_data():
    return gzip_content(NVD_ALL)


def commit_cve(session, cves):
    for cve in cves["CVE_Items"]:
        cve_id = cve["cve"]["CVE_data_meta"]["ID"]
        if not session.get(NVD, cve=cve_id):
            ed_user = NVD(cve=cve_id, data=cve)
            session.add(ed_user)
    session.commit()

