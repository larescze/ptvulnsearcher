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
class cve(database.Model): #Receipe class in the video
    id = database.Column(database.Integer(), primary_key=True)
    cve_id = database.Column(database.String(17), nullable = False)
    cwe_id = database.Column(database.String(15), nullable = True)
    cvss_vector = database.Column(database.String(40), nullable = True)
    cvss_score = database.Column(database.Float, nullable = True)
    description = database.Column(database.Text, nullable = True)

    def __repr__(self):
        return f"resources(id = {self.id}, cve_id = {self.cve_id}, cwe_id = {self.cwe_id}, cvss_vector={self.cvss_vector}, cvss_score={self.cvss_score}.description={self.description})"


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
        result = cve.query.get(cve_id)
        if result:
            return result.info()
        else:
            abort(404)

#Registering resources
api.add_resource(resources, "/<cve_id>")


#Instantiation
app.run(debug=True)
res = resources()
res.get()