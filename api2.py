from sqlalchemy import String, Integer, Float, Text, Column, ForeignKey
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import relationship, Session
from sqlalchemy import create_engine
from sqlalchemy import select


#PostgreSQL connection

#Isolation level = the ability of a database to allow a transaction to execute as if there are no other concurently running transactions. The goal is to prevent reads and writes of temporary/aborted or othewise incorrected data written by concurrent transaction
#Create an engine = creates new database connection

engine = create_engine("postgresql+psycopg2://postgres:postgres@localhost/postgres", isolation_level = "AUTOCOMMIT")



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


    def __repr__(self) -> str: # "-> str" means that function returns a String type
        return f"Cve(cve_id = {self.cve_id}, cwe_id = {self.cwe_id}, cvss_vector={self.cvss_vector}, cvss_score={self.cvss_score}, description={self.description})"
    


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

    

    def __repr__(self) -> str: # "-> str" means that function returns a String type
        return f"Vendor(product_id = {self.product_id}, cveid = {self.cveid}, cvce_id={self.cve_id}, vendor={self.vendor},product_type={self.product_type}, product_name = {self.product_name}, version = {self.version})"
  
    




with Session(engine) as session:
    results = session.query(Cve, Vendor).join("vendors").filter_by(cve_id = "CVE-1999-0001")

print(results)