from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from marshmallow import Schema, fields


#DB connection
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://postgres:postgres@localhost/postgres"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

database = SQLAlchemy(app)


#Creating model

class cveTable(database.Model): #Receipe class in the video
    id = database.Column(database.Integer(),primary_key=True)
    cve_id = database.Column(database.String(17), nullable = False)
    cwe_id = database.Column(database.String(15), nullable = True)
    cvss_vector = database.Column(database.String(40), nullable = True)
    cvss_score = database.Column(database.Float, nullable = True)
    description = database.Column(database.Text, nullable = True)


class vendorTable(database.Model):
    product_id = database.Column(database.Integer(),primary_key=True)
    cve_id = database.Column(database.String(17), nullable = False)
    vendor = database.Column(database.Text, nullable = True)
    product_type = database.Column(database.String(11), nullable = True)
    product_name = database.Column(database.Text, nullable = True)
    version = database.Column(database.String(8), nullable = True)

@classmethod
def get_record_by_cve_id(cls,cve_id):
    """Method that looks for and object and if it doesn't exit 404 is returned"""
    return cls.query.get_or_404(cve_id)

def commit(self):
    database.session.commit()


#Creating serializer with 'marshmallow'
class RecordsSchema(Schema):
    #Specifieng the fields for the schema
    id = fields.Integer()
    cve_id = fields.String()
    cwe_id = fields.String()
    cvss_vector  =fields.String()
    cvss_score = fields.Float()
    description = fields.String()
    #CONTINUE WITH FIELDS OF 'vendor' TABLE



@app.route("/cve/<String:cve_id>", method=["GET"])
def GetRecordBy_cve_id(cve_id):
    pass


    

app.run()