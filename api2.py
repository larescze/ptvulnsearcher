from sqlalchemy import ForeignKey
from sqlalchemy import String, Integer, Float, Text
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mappped_column
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from sqlalchemy import select
from sqlalchemy import Session

#PostgreSQL connection

#Isolation level = the ability of a database to allow a transaction to execute as if there are no other concurently running transactions. The goal is to prevent reads and writes of temporary/aborted or othewise incorrected data written by concurrent transaction
#Create an engine = creates new database connection

engine = create_engine("postgresql+psycopg2://postgres:postgres@localhost/postgres", isolation_level = "AUTOCOMMIT")


#Declaring models
class Base(DeclarativeBase): 
    pass


#Class "Cve" refering to "cve" table in the database
class Cve(Base):
    __tablename__ = "cve" #The reference mentioned above is made based on value of "__tablename__"

    id: Mapped[int] = mappped_column(primary_key = True)
    cve_id: Mapped[str] = mappped_column(String(17))
    cwe_id: Mapped[str] = mappped_column(String(15))
    cvss_vector: Mapped[str] = mappped_column(String(40))
    cvss_score: Mapped[float] = mappped_column(Float)
    description: Mapped[str] = mappped_column(Text)

    #Declaring relationship
    vendors: Mapped[list["Vendor"]] = relationship(backpopulates="cve_", cascade="all, delete-orphan")

    def __repr__(self) -> str: # "-> str" means that function returns a String type
        return f"Cve(cve_id = {self.cve_id}, cwe_id = {self.cwe_id}, cvss_vector={self.cvss_vector}, cvss_score={self.cvss_score}, description={self.description})"
    


#Class "Vendor" refering to "vendor" table in the database
class Vendor(Base):
    __tablename__ = "vendor" #The reference mentioned above is made based on value of "__tablename__"

    #Nullability is done by using 'Optional[]'
    product_id: Mapped[int] = mappped_column(primary_key = True)
    cveid: Mapped[int] = mappped_column(ForeignKey("cve.id"))
    cve_id: Mapped[str] = mappped_column(String(17))
    vendor: Mapped[str] = mappped_column(Text)
    product_type: Mapped[str] = mappped_column(String(11))
    product_name: Mapped[str] = mappped_column(Text)
    version: Mapped[str] = mappped_column(String(8))

    def __repr__(self) -> str: # "-> str" means that function returns a String type
        return f"Vendor(product_id = {self.product_id}, cveid = {self.cveid}, cvce_id={self.cve_id}, vendor={self.vendor},product_type={self.product_type}, product_name = {self.product_name}, version = {self.version})"
  
    #Declaring relationship
    cve_ :Mapped["Cve"] = relationship(back_populates="vendors")


session = Session(engine)
stmp = select(Cve).where(Cve.cve_id == "CVE-1999-0001")
for record in session.scalars(stmp):
    print(record)