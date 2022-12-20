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


#PostgreSQL connection

#Isolation level = the ability of a database to allow a transaction to execute as if there are no other concurently running transactions. The goal is to prevent reads and writes of temporary/aborted or othewise incorrected data written by concurrent transaction
#Create an engine = creates new database connection
app = Flask(__name__)
engine = create_engine("postgresql+psycopg2://postgres:postgres@localhost/postgres", isolation_level = "AUTOCOMMIT", echo = True)



#Declaring declarative base class
Base = declarative_base()


#Class "Cve" refering to "cve" table in the database
class Cve(Base):
    __tablename__ = "cve" #The reference mentioned above is made based on value of "__tablename__"

    id = Column(primary_key = True)
    cve_id = Column(String(17))
    cwe_id = Column(String(15))
    cvss_vector = Column(String(40))
    cvss_score = Column(Float)
    description = Column(Text)
    
     #Declaring relationship
    vendors = relationship("Vendor", back_populates = "cve_")

    #Serilization into JSON
    @property
    def serialized(self): # "-> str" means that function returns a String type
        return {"cve_id": self.cve_id, 
                "cwe_id":self.cwe_id, 
                "cvss_vector":self.cvss_vector, 
                "cvss_score":self.cvss_score, 
                "description":self.description,
        }
    

#Class "Vendor" refering to "vendor" table in the database
class Vendor(Base):
    __tablename__ = "vendor" #The reference mentioned above is made based on value of "__tablename__"

    #Nullability is done by using 'Optional[]'
    product_id = Column(primary_key = True)
    cveid = Column(ForeignKey("cve.id"))
    cve_id = Column(String(17))
    vendor = Column(Text)
    product_type = Column(String(11))
    product_name = Column(Text)
    version = Column(String(8))

    #Declaring relationship
    cve_ = relationship("Cve" , back_populates="vendors")

    #Serilization into JSON
    @property
    def serialized(self):
        return{"product_id":self.product_id, 
                "cveid":self.cveid, 
                "cvce_id":self.cve_id, 
                "vendor":self.vendor,
                "product_type":self.product_type, 
                "product_name":self.product_name, 
                "version":self.version,
            }
    
@app.route("/api/cve/<string:cve_id>")
def query_based_on_cve_id(cve_id):
    with Session(engine) as session:
        result = []
        statement = session.query(Vendor).join(Cve.vendors).filter(Cve.cve_id == cve_id)
        return jsonify({
        'result': [result.serialized for result in statement]
    })



#Query based on vendor's name
@app.route("/api/vendor/<string:vendor>")
def query_by_vendors_name(vendor):
    with Session(engine) as session:
        statement = session.query(Vendor).join(Cve.vendors).filter(Vendor.vendor == vendor)
        return jsonify({'result': [result.serialized for result in statement]})

#Quer based on vendor's name and product of that vendor
@app.route("/api/vendor/<string:vendor>/product/<string:product_name>")
def query_by_vendors_name_productname(vendor, product_name):
    with Session(engine) as session:
        statement = session.query(Vendor).join(Cve.vendors).filter(Vendor.vendor == vendor, Vendor.product_name == product_name)
        return jsonify({'result': [result.serialized for result in statement]})

#Query based on vendor's name, product of that vendor and also version of that product
@app.route("/api/vendor/<string:vendor>/product/<string:product_name>/version/<string:version>")
def query_by_vendors_name_productname_productversion(vendor, product_name, version):
    with Session(engine) as session:
        statement = session.query(Vendor).join(Cve.vendors).filter(Vendor.vendor ==vendor, Vendor.product_name == product_name, Vendor.version == version)
        return jsonify({'result': [result.serialized for result in statement]})

#Querz based on product's name
@app.route("/api/product/<string:product_name>")
def query_by_product_name(product_name):
    with Session(engine) as session:
        statement = session.query(Vendor).join(Cve.vendors).filter(Vendor.product_name == product_name)
        return jsonify({'result': [result.serialized for result in statement]})

#Query based on product's name and version of that product
@app.route("/api/product/<string:product_name>/version/<string:version>")
def query_by_productname_version(product_name, version):
    with Session(engine) as session:
        statement = session.query(Vendor).join(Cve.vendors).filter(Vendor.product_name == product_name, Vendor.version == version)
        return jsonify({'result': [result.serialized for result in statement]})



if __name__ == "__main__":
    app.run(debug=True)
   

