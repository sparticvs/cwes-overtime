from sqlalchemy.orm import (
        declarative_base,
        relationship
        )
from sqlalchemy import (
        Table,
        Column,
        ForeignKey
        )
from sqlalchemy.types import (
        Integer,
        String,
        DateTime,
        Text,
        Float
        )

Base = declarative_base()

advisory = Table(
        'advisories', Base.metadata,
        Column('cve_id', Integer, ForeignKey('cves.id')),
        Column('rhsa_id', Integer, ForeignKey('rhsas.id')))

affectedPackages = Table(
        'affected_packages', Base.metadata,
        Column('cve_id', Integer, ForeignKey('cves.id')),
        Column('package_id', Integer, ForeignKey('packages.id')))

class CVE(Base):
    __tablename__ = 'cves'

    id = Column(Integer, primary_key=True)
    cve = Column(String, unique=True)
    severity = Column(String)
    public_date = Column(DateTime)
    bugzilla_id = Column(Integer)
    bugzilla_description = Column(Text)
    cvss_score = Column(Float)
    cvss_scoring_vector = Column(String)
    cwe = Column(String)
    resource_url = Column(String)
    cvss3_scoring_vector = Column(String)
    cvss3_score = Column(Float)

    advisories = relationship("RHSA", secondary=advisory)
    affected_packages = relationship("Package", secondary=affectedPackages)


class RHSA(Base):
    __tablename__ = 'rhsas'

    id = Column(Integer, primary_key=True)
    rhsa = Column(String, unique=True)

"""
class Advisory(Base):
    __tablename__ = 'advisories'

    cve_id = Column('cve_id', ForeignKey('CVE.id'), primary_key=True)
    rhsa_id = Column('rhsa_id', ForeignKey('RHSA.id'), primary_key=True)
"""

class Package(Base):
    __tablename__ = 'packages'

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    short_name = Column(String)

"""
class AffectedPackage(Base):
    __tablename__ = 'affected_packages'

    cve_id = Column(ForeignKey('CVE.id'), primary_key=True)
    package_id = Column(ForeignKey('Package.id'), primary_key=True)
"""
