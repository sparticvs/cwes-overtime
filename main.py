#!/usr/bin/env python3
import requests
import logging
import csv
import os
import sys
import re
from dateutil.parser import isoparse
from argparse import ArgumentParser
from configparser import ConfigParser
from redhat.CVE import *
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DEFAULT_CONF_PATH = '~/.config/cwes-overtime/config.cfg'
#PKG_REGEX = r'-[0-9]+([-_+:\.0-9]+|el[8-9]|module|[a-fA-Fpg]|cvs|hg|svn|git|rc)+$'
PKG_REGEX = r'^([\/_a-zA-Z]|(?<!-)\d|-(?!\d))+'

logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
log = logging.getLogger(__name__)
session = sessionmaker()

def get_session(engine=None):
    global session
    if engine != None:
        session.configure(bind=engine)

    return session()

def create_config(path):
    default_cfg = """[default]
cache_file = ~/.config/cwes-overtime/cache
log_level = debug
api_host = https://access.redhat.com/hydra/rest/securitydata
"""
    log.debug('Creating default config at {}'.format(path))
    (head, tail) = os.path.split(path)
    try:
        os.makedirs(os.path.expanduser(head))
    except FileExistsError:
        log.debug('Ok, it exists, geez')
    cfg = open(os.path.expanduser(path), 'w')
    cfg.write(default_cfg)
    cfg.close()

def open_or_create_config(path):
    do_create = False
    try:
        os.stat(os.path.expanduser(path))
    except FileNotFoundError:
        do_create = True

    if do_create:
        create_config(path)

    config = ConfigParser()
    config.read(os.path.expanduser(path))
    return config

def open_or_create_cache(path):
    do_create = False
    try:
        os.stat(os.path.expanduser(path+'/cache.db'))
    except FileNotFoundError:
        log.debug("Cache not found, will create")
        do_create = True

    if do_create:
        try:
            os.makedirs(os.path.expanduser(path))
        except FileExistsError:
            log.debug("Cache dir already exists")

    eng_str = 'sqlite:///' + os.path.expanduser(path) + '/cache.db'
    log.debug('Connecting to engine {}'.format(eng_str))
    engine = create_engine(eng_str)
    
    if do_create:
        log.debug('Creating all tables')
        Base.metadata.create_all(engine)

    sess = get_session(engine)
    sess.commit()

class ResponseNotOkException(Exception): pass

class EmptyResponseException(Exception): pass

def get_data(host, query):
    full_query = host + query
    r = requests.get(full_query)

    if r.status_code != 200: 
        log.error('Invalid request; returned {} for the following '
                  'query:\n{}'.format(r.status_code, full_query))
        raise ResponseNotOkException

    if not r.json():
        log.warn('No data returned with the following
                query:'.format(full_query))
        raise EmptyResponseException

    return r.json()


if __name__ == "__main__":
    parser = ArgumentParser(description="Create CSV of CVEs to CWEs over the \
                                            years for a specific package set")
    parser.add_argument("-c", "--cwes", help="List of CWEs", nargs='+',
            required=True)
    parser.add_argument("-p", "--packages", help="List of Packages", nargs='*')
    parser.add_argument("--config", help="Override default config path",
            default=os.path.expanduser(DEFAULT_CONF_PATH))
    args = parser.parse_args()
    
    cfg = open_or_create_config(args.config)
    log.setLevel(getattr(logging, cfg["default"]["log_level"].upper()))

    open_or_create_cache(cfg["default"]["cache_file"])

    api_host = cfg["default"]["api_host"]
    sess = get_session()

    rex_patt = re.compile(PKG_REGEX)
    
    pg = 0
    try:
        while True:
            pg += 1
            log.debug("Retreiving Page {}".format(pg))
            data = get_data(api_host, '/cve.json?page={}'.format(pg))

            for cve in data:
                new_cve = sess.query(CVE).filter_by(cve=cve["CVE"]).first()

                if new_cve == None:
                    log.debug("Creating CVE {}".format(cve["CVE"]))
                    date = cve.get("public_date", None)
                    if date is None:
                        date = '1970-01-01T00:00:00Z'
                    new_cve = CVE(cve=cve.get("CVE", None),
                        severity=cve.get("severity", None),
                        public_date=isoparse(date),
                        bugzilla_id=cve.get("bugzilla", None),
                        bugzilla_description=cve.get("bugzilla_description", None),
                        cvss_score=cve.get("cvss_score", None),
                        cvss_scoring_vector=cve.get("cvss_scoring_vector", None),
                        cwe=cve.get("CWE", None),
                        resource_url=cve.get("resource_url", None),
                        cvss3_scoring_vector=cve.get("cvss3_scoring_vector", None),
                        cvss3_score=cve.get("cvss3_score", None))
                    sess.add(new_cve)

                for advisory in cve["advisories"]:
                    new_rhsa = sess.query(RHSA).filter_by(rhsa=advisory).first()

                    if new_rhsa == None:
                        log.debug("Creating RHSA {}".format(advisory))
                        new_rhsa = RHSA(rhsa=advisory)
                        sess.add(new_rhsa)

                    new_cve.advisories.append(new_rhsa)

                for package in cve["affected_packages"]:
                    new_pkg = sess.query(Package).filter_by(name=package).first()

                    if new_pkg == None:
                        log.debug("Creating Package {}".format(package))
                        #short_name = rex_patt.sub('', package)
                        short_name = rex_patt.match(package)[0]
                        log.debug("Package Short Name {}".format(short_name))
                        new_pkg = Package(name=package, short_name=short_name)
                        sess.add(new_pkg)
                    new_cve.affected_packages.append(new_pkg)

                sess.commit()
    except ResponseNotOkException:
        pass
    except EmptyResponseException:
        pass

