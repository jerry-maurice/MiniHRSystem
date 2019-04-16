from sqlalchemy import Column, ForeignKey, Integer, String, Date, DateTime
from sqlalchemy import Float, Text, Boolean, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine

from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)

import random, string, datetime

# database config
from config import DB_USER, DB_PASSWORD, DB_END, DB_PORT, DB_DATABASE

Base = declarative_base()
secret_key = ''.join(random.choice(string.ascii_uppercase +
                                   string.digits) for x in range(32))

''' About User'''
class User(Base):
    # store user info
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    picture = Column(String(250))
    title = Column(String(50))
    email = Column(String(250), index=True)
    password_hash = Column(String(250), nullable=False)
    note = relationship('Note', backref='user')

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(secret_key, expires_in=expiration)
        return s.dumps({'id':self.id})

    def is_active(self):
        return True

    def get_id(self):
        return self.email

    def is_authenticated(self):
        return self.authenticated

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(secret_key)
        try:
            data=s.loads(token)
        except SignatureExpired:
            # Valid token but expired
            return None
        except BadSignature:
            return None
        user_id = data['id']
        return user_id

    @property
    def serialize(self):
        return{
            'id':self.id,
            'email':self.email,
            'title':self.title
            }


'''About Employee '''
class Department(Base):
    # store all the department
    __tablename__ = 'department'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    description = Column(Text)
    employee = relationship('Employee', backref='department')

    @property
    def serialize(self):
        return{
            'id':self.id,
            'name': self.name,
            'description': self.description
            }


class Employee(Base):
    # manage and store employee info
    __tablename__ = 'employee'
    id = Column(Integer, primary_key=True)
    picture = Column(String(250))
    firstName = Column(String(250), nullable = False)
    lastName = Column(String(250), nullable=False)
    middleName = Column(String(250))
    birthdate = Column(Date)
    email = Column(String(250))
    ssn = Column(String(9))
    gender = Column(String(10))
    homePhone = Column(String(15))
    cellPhone = Column(String(15))
    address = Column(String(250))
    city = Column(String(50))
    zipCode = Column(String(5))
    State = Column(String(20))
    hiringDate = Column(Date)
    title = Column(String(250))
    payRate = Column(Float)
    status = Column(String(50), nullable=False, default='Active')
    rating = Column(Integer)
    department_id = Column(Integer, ForeignKey('department.id'))
    education = relationship('Education', backref='employee')
    note = relationship('Note', backref='employee')
    training = relationship('Training', backref='employee')
    documents = relationship('Documents', backref='employee')
    emergency = relationship('Emergency', backref='employee')
    boarding = relationship('Onboarding', backref='employee')

    @property
    def serialize(self):
        return{
            'id':self.id,
            'picture':self.picture,
            'firstName':self.firstName,
            'lastName':self.lastName,
            'middleName':self.middleName,
            'birthdate':self.birthdate,
            'email':self.email,
            'ssn':self.ssn,
            'gender':self.gender,
            'homePhone':self.homePhone,
            'cellPhone':self.cellPhone,
            'address':self.address,
            'city':self.city,
            'zipCode':self.zipCode,
            'State':self.State,
            'hiringDate':self.hiringDate,
            'title':self.title,
            'payRate':self.payRate,
            'status':self.status,
            'rating':self.rating,
            'departmentId':self.department_id
            }


class Education(Base):
    # inside education
    __tablename__ = 'education'
    id = Column(Integer, primary_key=True)
    institution = Column(String(250), nullable=False)
    major = Column(String(250))
    start = Column(Date)
    end = Column(Date)
    employee_id = Column(Integer, ForeignKey('employee.id'))

    @property
    def serialize(self):
        return{
            'id':self.id,
            'institution':self.institution,
            'major':self.major,
            'start':self.start,
            'end':self.end,
            'employeeId':self.employee_id
            }


class Note(Base):
    # inside note
    __tablename__ = 'note'
    id = Column(Integer, primary_key=True)
    body = Column(Text, nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    employee_id = Column(Integer, ForeignKey('employee.id'))

    @property
    def serialize(self):
        return{
            'id':self.id,
            'body':self.body,
            'user_id':self.user_id,
            'employeeId':self.employee_id
            }


class Traininglist(Base):
    # list of training 
    __tablename__ = 'traininglist'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    description = Column(Text)
    training = relationship('Training', backref='traininglist')

    @property
    def serialize(self):
        return{
            'id':self.id,
            'name':self.name,
            'description':self.description
            }


class Training(Base):
    # inside training
    __tablename__ = 'training'
    id = Column(Integer, primary_key=True)
    traininglist_id = Column(Integer, ForeignKey('traininglist.id'))
    provided = Column(Date, default=datetime.datetime.utcnow)
    due = Column(Date)
    employee_id = Column(Integer, ForeignKey('employee.id'))

    @property
    def serialize(self):
        return{
            'id':self.id,
            'provided':self.provided,
            'due':self.due,
            'trainingListID':self.traininglist_id,
            'employeeId':self.employee_id
            }


class Documents(Base):
    # list of document for each employee
    __tablename__ = 'documents'
    id  = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    category = Column(String(250), nullable=False)
    employee_id = Column(Integer, ForeignKey('employee.id'))

    @property
    def serialize(self):
        return{
            'id':self.id,
            'name':self.name,
            'category':self.category,
            'employeeId':self.employee_id
            }


class Emergency(Base):
    # employee emergency contact
    __tablename__ = 'emergency'
    id = Column(Integer, primary_key=True)
    firstName = Column(String(250), nullable=False)
    lastName = Column(String(250), nullable=False)
    homePhone = Column(String(15))
    cellPhone = Column(String(15))
    employee_id = Column(Integer, ForeignKey('employee.id'))

    @property
    def serialize(self):
        return{
            'id':self.id,
            'firstName':self.firstName,
            'lastName':self.lastName,
            'homePhone':self.homePhone,
            'cellPhone':self.cellPhone,
            'employeeId':self.employee_id
            }


class Onboardinglist(Base):
    # contain list of onboarding task create by company
    __tablename__ = 'onboardinglist'
    id = Column(Integer, primary_key=True)
    name = Column(String(250))
    description = Column(Text)
    onboarding = relationship('Onboarding', backref='onboardinglist')

    @property
    def serialize(self):
        return{
            'id':self.id,
            'name':self.name,
            'description':self.description
            }


class Onboarding(Base):
    # employee requirement needed
    __tablename__ = 'onboarding'
    id = Column(Integer, primary_key=True)
    provided = Column(Date, nullable=False)
    expired = Column(Date, nullable=True)
    employee_id = Column(Integer, ForeignKey('employee.id'))
    onboardinglist_id = Column(Integer, ForeignKey('onboardinglist.id'))

    @property
    def serialize(self):
        return{
            'id':self.id,
            'provided':self.provided,
            'expired':self.expired,
            'onboardingListId':self.onboardinglist_id,
            'employeeId':self.employee_id
            }


linking_members = Table('linking', Base.metadata,
                        Column('patientId', Integer, ForeignKey('patient.id')),
                        Column('employeeId', Integer, ForeignKey('employee.id'))
                        )


'''About Patient '''
class Patient(Base):
    # inside patient class
    __tablename__ = 'patient'
    id = Column(Integer, primary_key=True)
    patientId = Column(String(15), nullable=False)
    firstName = Column(String(250), nullable=False)
    lastName = Column(String(250), nullable=False)
    middleName = Column(String(250))
    birthdate = Column(Date)
    gender = Column(String(10))
    homePhone = Column(String(15))
    cellPhone = Column(String(15))
    address = Column(String(250))
    city = Column(String(50))
    zipCode = Column(String(5))
    State = Column(String(20))
    status = Column(String(50), nullable=False)
    care = relationship('Employee', secondary=linking_members, backref="Patient")

    @property
    def serialize(self):
        return{
            'id':self.id,
            'patientId':self.provided,
            'firstName':self.firstName,
            'lastName':self.lastName,
            'middleName':self.middleName,
            'birthdate':self.birthdate,
            'gender':self.gender,
            'homePhone':self.homePhone,
            'cellPhone':self.cellPhone,
            'address':self.address,
            'city':self.city,
            'zipCode':self.zipCode,
            'State':self.State,
            'status':self.status
            }


'''About Company '''
class Company(Base):
    # detail about company
    __tablename__ = 'company'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)

    @property
    def serialize(self):
        return{
            'id':self.id,
            'name':self.name
            }


class CompanyLinks(Base):
    # store usefull links used by the company
    __tablename__ = 'companylinks'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    link = Column(Text, nullable=False)

    @property
    def serialize(self):
        return{
            'id':self.id,
            'name':self.name,
            'link':self.link
            }


engine = create_engine('mysql+pymysql://'+DB_USER+':'+DB_PASSWORD+'@'+DB_END+':'+DB_PORT+'/'
                     +DB_DATABASE)
Base.metadata.create_all(engine)
