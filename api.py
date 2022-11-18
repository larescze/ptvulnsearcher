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
class CveTableModel(database.Model): #Receipe class in the video
    id = database.Column(database.Integer(),primary_key=True)
    cve_id = database.Column(database.String(17), nullable = False)
    cwe_id = database.Column(database.String(15), nullable = True)
    cvss_vector = database.Column(database.String(40), nullable = True)
    cvss_score = database.Column(database.Float, nullable = True)
    description = database.Column(database.Text, nullable = True)

    def __repr__(self):
        return f"Record(id = {self.id}, cve_id = {self.cve_id}, cwe_id = {self.cwe_id})"

"""
class vendorTable(database.Model):
    product_id = database.Column(database.Integer(),primary_key=True)
    cve_id = database.Column(database.String(17), nullable = False)
    vendor = database.Column(database.Text, nullable = True)
    product_type = database.Column(database.String(11), nullable = True)
    product_name = database.Column(database.Text, nullable = True)
    version = database.Column(database.String(8), nullable = True)"""

#Serilization
resources_fields = {
    "id":fields.Integer,
    "cve_id":fields.String,
    "cwe_id":fields.String,
    "cvss_vector":fields.String,
    "cvss_score":fields.Float,
    "description":fields.String

}

#Resources
class resources(Resource):
    @marshal_with(resources_fields)#Serilize the returned object according to 'resource_fields'
    def get(self, cve_id):
        result = CveTableModel.query.get(cve_id = CveTableModel.cve_id)
        return result



#Registering resources
api.add_resource(resources, "/<String:cve_id>")




app.run(debug=True)