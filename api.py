#!/usr/bin/python3
from os import abort
from sqlalchemy import String, Integer, Float, Text, Column, ForeignKey, or_, and_
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import relationship, Session
from sqlalchemy import create_engine
from sqlalchemy import select
from flask import Flask, jsonify
from flask_restful import Api, Resource, fields, marshal_with
import json
import os


#PostgreSQL connection
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

    """def __repr__(self) -> str: # "-> str" means that function returns a String type
        return f"Cve(cve_id = {self.cve_id}, cwe_id = {self.cwe_id}, cvss_vector={self.cvss_vector}, cvss_score={self.cvss_score}, description={self.description})"

    #Serilization into JSON
    @property
    def serialized(self):
        return {"cve_id": self.cve_id, 
                "cwe_id":self.cwe_id, 
                "cvss_vector":self.cvss_vector, 
                "cvss_score":self.cvss_score, 
                "description":self.description,}"""
    
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

    """def __repr__(self) -> str: # "-> str" means that function returns a String type
        return f"Vendor(product_id = {self.product_id}, cveid = {self.cveid}, vendor={self.vendor},product_type={self.product_type}, product_name = {self.product_name}, version = {self.version})"

    #Serilization into JSON
    @property
    def serialized(self):
        return{"product_id":self.product_id, 
                "cveid":self.cveid, 
                "vendor":self.vendor,
                "product_type":self.product_type, 
                "product_name":self.product_name, 
                "version":self.version,}"""


#Input sanitization
"""def input_sanitization(input):
    sanitized_input= ""
    potentially_dangerous = ['<','>','\'','\"',"AND","OR","SELECT","UNION","DROP","ALTER","FROM"]
    for content1 in input.split(' '):
        for content2 in potentially_dangerous:
            if (content1 == content2):
                sanitized_input = sanitized_input +"&t"
            else:
                sanitized_input = sanitized_input + content1
    return sanitized_input"""

   
@app.route("/api/v1/cve/<string:cve_id>")
def cve(cve_id):
    with Session(engine) as session:
        result = []
        statement = select(Cve.cve_id, Cve.cwe_id, Cve.cvss_vector,Cve.cvss_score, Cve.description, Vendor.vendor, Vendor.product_type, Vendor.product_name, Vendor.version).join(Cve.vendors).where(Cve.cve_id == cve_id)
        for row in session.execute(statement):
            result.append(dict(row))
        return jsonify(result)

#Query based on vendor's name
@app.route("/api/v1/vendor/<string:vendor>")
def vendor(vendor):
    with Session(engine) as session:
        result = []
        statement = select(Cve.cve_id, Cve.cwe_id, Cve.cvss_vector,Cve.cvss_score, Cve.description, Vendor.vendor, Vendor.product_type, Vendor.product_name, Vendor.version).join(Cve.vendors).where(Vendor.vendor == vendor)
        for row in session.execute(statement):
            result.append(dict(row))
        return jsonify(result)

#Query based on vendor's name and product' name of a vendor
@app.route("/api/v1/vendor/<string:vendor>/product/<string:product_name>")
def vendor_productname(vendor, product_name):
    with Session(engine) as session:
        result = []
        statement = select(Cve.cve_id, Cve.cwe_id, Cve.cvss_vector,Cve.cvss_score, Cve.description, Vendor.vendor, Vendor.product_type, Vendor.product_name, Vendor.version).join(Cve.vendors).where(Vendor.vendor == vendor).where(Vendor.product_name==product_name)
        for row in session.execute(statement):
            result.append(dict(row))
        return jsonify(result)

#Query based on vendor's name, product's name and version of the product of a vendor
@app.route("/api/v1/vendor/<string:vendor>/product/<string:product_name>/version/<string:version>")
def vendor_productname_version(vendor, product_name, version):
    with Session(engine) as session:
        result = []
        statement = select(Cve.cve_id, Cve.cwe_id, Cve.cvss_vector,Cve.cvss_score, Cve.description, Vendor.vendor, Vendor.product_type, Vendor.product_name, Vendor.version).join(Cve.vendors).where(Vendor.vendor == vendor).where(Vendor.product_name==product_name).where(Vendor.version==version)
        for row in session.execute(statement):
            result.append(dict(row))
        return jsonify(result)

#Query based on product's name
@app.route("/api/v1/product/<string:product_name>")
def product_name(product_name):
    with Session(engine) as session:
        result = []
        statement = select(Cve.cve_id, Cve.cwe_id, Cve.cvss_vector,Cve.cvss_score, Cve.description, Vendor.vendor, Vendor.product_type, Vendor.product_name, Vendor.version).join(Cve.vendors).where(Vendor.product_name==product_name)
        for row in session.execute(statement):
            result.append(dict(row))
        return jsonify(result)
        
#Query based on product's name and version of the product
@app.route("/api/v1/product/<string:product_name>/version/<string:version>")
def productname_version(product_name, version):
    with Session(engine) as session:
        result = []
        statement = select(Cve.cve_id, Cve.cwe_id, Cve.cvss_vector,Cve.cvss_score, Cve.description, Vendor.vendor, Vendor.product_type, Vendor.product_name, Vendor.version).join(Cve.vendors).where(Vendor.product_name==product_name).where(Vendor.version==version)
        for row in session.execute(statement):
            result.append(dict(row))
        return jsonify(result)    

if __name__ == "__main__":
    app.run(debug=True)
   

