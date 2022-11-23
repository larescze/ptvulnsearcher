import json
from os import abort
from flask import Flask, jsonify
from flask_restful import Api, Resource, fields, marshal_with
from flask_sqlalchemy import SQLAlchemy



#DB connection
app = Flask(__name__)
api = Api(app) #Wrap our app in an API 
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://postgres:postgres@localhost/postgres"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
database = SQLAlchemy(app)

#Models
class Cve(database.Model): #Receipe class in the video
    __tablename__ = "cve"
    id = database.Column(database.Integer(), nullable=True)
    cve_id = database.Column(database.String(17), primary_key = True, nullable =True)
    cwe_id = database.Column(database.String(15), nullable = True)
    cvss_vector = database.Column(database.String(40), nullable = True)
    cvss_score = database.Column(database.Float, nullable = True)
    description = database.Column(database.Text, nullable = True)
    
    #Defining relationship
    vendors = database.relationship("Vendor", backref="cve")
    
    def __repr__(self):
        return f"resources(id = {self.id}, cve_id = {self.cve_id}, cwe_id = {self.cwe_id}, cvss_vector={self.cvss_vector}, cvss_score={self.cvss_score}.description={self.description} product_id={Vendor.product_id}, cve_id={Vendor.cve_id}, vendor={Vendor.vendor}, product_type={Vendor.product_type}, product_name={Vendor.product_name}, version={Vendor.version})"
        #return f"resources(cve_id = {self.cve_id}, cwe_id = {self.cwe_id}, cvss_vector={self.cvss_vector}, cvss_score={self.cvss_score}.description={self.description})"

class Vendor(database.Model):
    __tablename__ = "vendor"
    product_id = database.Column(database.Integer(), primary_key = True)
    cve_id = database.Column(database.String(17), database.ForeignKey("cve.cve_id"), nullable = True)
    vendor = database.Column(database.Text, nullable = True)
    product_type = database.Column(database.String(11), nullable = True)
    product_name = database.Column(database.Text, nullable = True)
    version = database.Column(database.String(8), nullable = True)



#Serilization
resources_fields = {
    "id":fields.Integer,
    "cve_id":fields.String,
    "cwe_id":fields.String,
    "cvss_vector":fields.String,
    "cvss_score":fields.Float,
    "description":fields.String,
    "product_id":fields.Integer,
    "cve_id":fields.String,
    "vendor":fields.String,
    "product_type":fields.String,
    "product_name":fields.String,
    "version":fields.String
}

#Resources
class resources(Resource):
    @marshal_with(resources_fields)#Serilize the returned object according to 'resource_fields'
    def get(self, cve_id):
        result = Cve.query.join(Vendor).filter(Vendor.cve_id == cve_id).all()
        if result:
            return result
        else:
            abort(404)



#Registering resources
api.add_resource(resources, "/api/<cve_id>")


#Instantiation
app.run(debug=True)
res = resources()
res.get()

