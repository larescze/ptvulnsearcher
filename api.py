#!/usr/bin/python3
from sqlalchemy import String, Float, Text, Column, ForeignKey
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import relationship, Session
from sqlalchemy import create_engine
from sqlalchemy import select
from flask import Flask, json


app = Flask(__name__)

engine = create_engine("postgresql+psycopg2://postgres:postgres@localhost/postgres", isolation_level = "AUTOCOMMIT", echo = True)

#Declaration of declarative base class
Base = declarative_base()

#Class "Cve" refers to "cve" table in the database
class Cve(Base):
    __tablename__ = "cve" #The reference mentioned above is made based on value of "__tablename__"

    id = Column(primary_key = True)
    cve_id = Column(String(17))
    cwe_id = Column(String(15))
    cvss_vector = Column(String(40))
    cvss_score = Column(Float)
    description = Column(Text)
    
    #Relationship declaration
    vendors = relationship("Vendor", back_populates = "cve_")
  
#Class "Vendor" refers to "vendor" table in the database
class Vendor(Base):
    __tablename__ = "vendor" #The reference mentioned above is made based on value of "__tablename__"

    product_id = Column(primary_key = True)
    cveid = Column(ForeignKey("cve.id"))
    vendor = Column(Text)
    product_type = Column(String(11))
    product_name = Column(Text)
    version = Column(String(8))

    #Relationship declaration
    cve_ = relationship("Cve" , back_populates="vendors")
 
@app.route("/api/v1/cve/<string:cve_id>")
def cve(cve_id):
    with Session(engine) as session:
        with app.app_context():
            result = []
            statement = select(Cve.cve_id, Cve.cwe_id, Cve.cvss_vector,Cve.cvss_score, Cve.description, Vendor.vendor, Vendor.product_type, Vendor.product_name, Vendor.version).join(Cve.vendors).where(Cve.cve_id == cve_id)
            for row in session.execute(statement):
                result.append({'cve_id':row.cve_id, 'cwe_id':row.cwe_id, 'cvss_vector':row.cvss_vector,'cvss_score':row.cvss_score, 'description':row.description, 'vendor':row.vendor, 'product_type':row.product_type, 'product_name':row.product_name, 'version':row.version})
            return json.dumps(result, sort_keys=True, indent='\t', separators=(',', ': '))

#Query based on vendor's name
@app.route("/api/v1/vendor/<string:vendor>")
def vendor(vendor):
    with Session(engine) as session:
        with app.app_context():
            result = []
            statement = select(Cve.cve_id, Cve.cwe_id, Cve.cvss_vector,Cve.cvss_score, Cve.description, Vendor.vendor, Vendor.product_type, Vendor.product_name, Vendor.version).join(Cve.vendors).where(Vendor.vendor == vendor)
            for row in session.execute(statement):
                result.append({'cve_id':row.cve_id, 'cwe_id':row.cwe_id, 'cvss_vector':row.cvss_vector,'cvss_score':row.cvss_score, 'description':row.description, 'vendor':row.vendor, 'product_type':row.product_type, 'product_name':row.product_name, 'version':row.version})
            return json.dumps(result, sort_keys=True, indent='\t', separators=(',', ': '))

#Query based on vendor's name and product' name of a vendor
@app.route("/api/v1/vendor/<string:vendor>/product/<string:product_name>")
def vendor_productname(vendor, product_name):
    with Session(engine) as session:
        with app.app_context():
            result = []
            statement = select(Cve.cve_id, Cve.cwe_id, Cve.cvss_vector,Cve.cvss_score, Cve.description, Vendor.vendor, Vendor.product_type, Vendor.product_name, Vendor.version).join(Cve.vendors).where(Vendor.vendor == vendor).where(Vendor.product_name==product_name)
            for row in session.execute(statement):
                result.append({'cve_id':row.cve_id, 'cwe_id':row.cwe_id, 'cvss_vector':row.cvss_vector,'cvss_score':row.cvss_score, 'description':row.description, 'vendor':row.vendor, 'product_type':row.product_type, 'product_name':row.product_name, 'version':row.version})
            return json.dumps(result, sort_keys=True, indent='\t', separators=(',', ': '))

#Query based on vendor's name, product's name and version of the product of a vendor
@app.route("/api/v1/vendor/<string:vendor>/product/<string:product_name>/version/<string:version>")
def vendor_productname_version(vendor, product_name, version):
    with Session(engine) as session:
        with app.app_context():
            result = []
            statement = select(Cve.cve_id, Cve.cwe_id, Cve.cvss_vector,Cve.cvss_score, Cve.description, Vendor.vendor, Vendor.product_type, Vendor.product_name, Vendor.version).join(Cve.vendors).where(Vendor.vendor == vendor).where(Vendor.product_name==product_name).where(Vendor.version==version)
            for row in session.execute(statement):
                result.append({'cve_id':row.cve_id, 'cwe_id':row.cwe_id, 'cvss_vector':row.cvss_vector,'cvss_score':row.cvss_score, 'description':row.description, 'vendor':row.vendor, 'product_type':row.product_type, 'product_name':row.product_name, 'version':row.version})
            return json.dumps(result, sort_keys=True, indent='\t', separators=(',', ': '))

#Query based on product's name
@app.route("/api/v1/product/<string:product_name>")
def product_name(product_name):
    with Session(engine) as session:
        with app.app_context():
            result = []
            statement = select(Cve.cve_id, Cve.cwe_id, Cve.cvss_vector,Cve.cvss_score, Cve.description, Vendor.vendor, Vendor.product_type, Vendor.product_name, Vendor.version).join(Cve.vendors).where(Vendor.product_name==product_name)
            for row in session.execute(statement):
                result.append({'cve_id':row.cve_id, 'cwe_id':row.cwe_id, 'cvss_vector':row.cvss_vector,'cvss_score':row.cvss_score, 'description':row.description, 'vendor':row.vendor, 'product_type':row.product_type, 'product_name':row.product_name, 'version':row.version})
            return json.dumps(result, sort_keys=True, indent='\t', separators=(',', ': '))
        
#Query based on product's name and version of the product
@app.route("/api/v1/product/<string:product_name>/version/<string:version>")
def productname_version(product_name, version):
    with Session(engine) as session:
        with app.app_context():
            result = []
            statement = select(Cve.cve_id, Cve.cwe_id, Cve.cvss_vector,Cve.cvss_score, Cve.description, Vendor.vendor, Vendor.product_type, Vendor.product_name, Vendor.version).join(Cve.vendors).where(Vendor.product_name==product_name).where(Vendor.version==version)
            for row in session.execute(statement):
                result.append({'cve_id':row.cve_id, 'cwe_id':row.cwe_id, 'cvss_vector':row.cvss_vector,'cvss_score':row.cvss_score, 'description':row.description, 'vendor':row.vendor, 'product_type':row.product_type, 'product_name':row.product_name, 'version':row.version})
            return json.dumps(result, sort_keys=True, indent='\t', separators=(',', ': '))    

if __name__ == "__main__":
    #app.run(debug=True)
    app.run()
    
   

