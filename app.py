# !/usr/bin/env python3
# importing
from flask import Flask, request, redirect, render_template
from flask import jsonify, url_for, flash, abort, g
from flask import session as login_session
from flask import make_response
from flask_httpauth import HTTPBasicAuth

# importing from database
from sqlalchemy import create_engine, asc
from sqlalchemy import func
from sqlalchemy.orm import sessionmaker
from models import Base, Department, Employee, Education, Company
from models import Emergency, Onboardinglist, Onboarding
from models import Note, Traininglist, Training, CompanyLinks
from models import Documents, User, Patient


from flask_login import LoginManager, UserMixin, login_required, login_user
from flask_login import logout_user
from werkzeug.utils import secure_filename

import random, string, json, time

from redis import Redis
from functools import update_wrapper

# database config
from config import DB_USER, DB_PASSWORD, DB_END, DB_PORT, DB_DATABASE


# initialisation
app = Flask(__name__)
auth = HTTPBasicAuth()
engine=create_engine('mysql+pymysql://'+DB_USER+':'+DB_PASSWORD+'@'+DB_END+':'+DB_PORT+'/'
                     +DB_DATABASE)
Base.metadata.bin = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
redis = Redis()


# control the usage of the api
class RateLimit(object):
    expiration_window = 10

    def __init__(self, key_prefix, limit, per, send_x_headers):
        self.reset = (int(time.time()) // per) * per + per
        self.key = key_prefix + str(self.reset)
        self.limit = limit
        self.per = per
        self.send_x_headers = send_x_headers
        p = redis.pipeline()
        p.incr(self.key)
        p.expireat(self.key, self.reset + self.expiration_window)
        self.current = min(p.execute()[0], limit)

    remaining = property(lambda x: x.limit - x.current)
    over_limit = property(lambda x: x.current >= x.limit)

def get_view_rate_limit():
    return getattr(g, '_view_rate_limit', None)

def on_over_limit(limit):
    return 'You hit the rate limit', 400

def ratelimit(limit, per=300, send_x_headers=True,
              over_limit=on_over_limit,
              scope_func=lambda: request.remote_addr,
              key_func=lambda: request.endpoint):
    def decorator(f):
        def rate_limited(*args, **kwargs):
            key = 'rate-limit/%s/%s/' % (key_func(), scope_func())
            rlimit = RateLimit(key, limit, per, send_x_headers)
            g._view_rate_limit = rlimit
            if over_limit is not None and rlimit.over_limit:
                return over_limit(rlimit)
            return f(*args, **kwargs)
        return update_wrapper(rate_limited, f)
    return decorator


@app.after_request
def inject_x_rate_headers(response):
    limit = get_view_rate_limit()
    if limit and limit.send_x_headers:
        h = response.headers
        h.add('X-RateLimit-Remaining', str(limit.remaining))
        h.add('X-RateLimit-Limit', str(limit.limit))
        h.add('X-RateLimit-Reset', str(limit.reset))
    return response


# security
@auth.verify_password
def verify_password(username_or_token, password):
    # verify if it is token
    user_id = User.verify_auth_token(username_or_token)
    if user_id:
        user = session.query(User).filter_by(id=user_id).one()
    else:
        user = session.query(User).filter_by(email=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@app.route('/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token':token.decode('ascii')})


# register new user
@app.route("/v1/users/register", methods=['POST'])
def registerUser():
    email = request.args.get('email','')
    password = request.args.get('password','')
    repassword = request.args.get('repassword')
    if email is None or password is None:
        app.logger.info("missing arguments")
        abort(400)
    if session.query(User).filter_by(email=email).first() is not None:
        app.logger.info("existing user")
        user = session.query(User).filter_by(email=email).first()
        return jsonify(
            {'message':'user already exists'}
            ), 200#,{'Location':url_for('get_user', id = user.id, _external = True)}
    if password == repassword:
        user = User(email=email)
        user.hash_password(password)
        session.add(user)
        session.commit()
        return jsonify(
            { 'email': user.email }
            ), 201#,{'Location': url_for('get_user', id = user.id, _external = True)}
    else:
        return jsonify(
            { 'message': 'password do not match' }
            ), 200#,{'Location': url_for('get_user', id = user.id, _external = True)}


# get user
@app.route('/v1/users/<int:id>')
def get_user(id):
    user = session.query(User).filter_by(id=id).one()
    if not user:
        abort(400)
    return jsonify({'email':user.email})


# login
@app.route('/v1/login', methods=['POST'])
def login():
    email = (request.args.get('email',''))
    password = (request.args.get('password',''))
    if email == None or password == None:
        return jsonify(
            {'message':'email or password not provided'}
            ),200#,{'Location':url_for('login')}
    else:
        user = session.query(User).filter_by(email=email).first()
        if not user or not user.verify_password(password):
            return jsonify({'message':'Unrecognized Provider'})
        app.logger.info("user login successfully %s" %email)
        token = user.generate_auth_token(600)
        return jsonify({'token':token.decode('ascii')})


''' editing, deleting, updating and getting user account '''

# edit account
@app.route('/v1/users/<int:user_id>', methods=['GET','PUT','DELETE'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def editAccount(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    # getting account
    if request.method == 'GET':
        return jsonify(user = user.serialize)
    # editing account
    if request.method == 'PUT':
        app.logger.info('editing user')
        picture = request.args.get('picture','')
        title = request.args.get('title','')
        email = request.args.get('email','')
        password = request.args.get('password','')
        if picture:
            user.picture = str(picture)
        if title:
            user.title = str(title)
        if email:
            user.email = str(email)
        if password:
            user.hash_password((password))
        session.add(user)
        session.commit()
        return jsonify({'message':
                        'user with email %s has been updated ' %user.email})
    if request.method == 'DELETE':
        # deleting user
        session.delete(user)
        session.commit()
        return jsonify({'message':'user has been deleted'})


# view all account
@app.route('/v1/users/all', methods=['GET'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def viewAllAccounts():
    accounts = session.query(User).all()
    if request.method == 'GET':
        return jsonify(users = [i.serialize for i in accounts])


''' editing, deleting, updating and getting departments '''

# view and modify department
@app.route('/v1/departments/<int:id>', methods=['GET','PUT','DELETE'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def editDepartment(id):
    app.logger.info('editing department')
    department = session.query(Department).filter_by(id=id).one()
    # view selected department
    if request.method == 'GET':
        return jsonify(department=department.serialize)
    # updating department
    if request.method == 'PUT':
        name = request.args.get('name','')
        description = request.args.get('description','')
        if name:
            department.name = str(name)
        if description:
            department.description = (description)
        session.add(department)
        session.commit()
        return jsonify({'message':
                        'department with name %s has been updated ' %department.name})
    if request.method == 'DELETE':
        # deleting department
        session.delete(department)
        session.commit()
        return jsonify({'message':'department has been deleted'})


# adding a new department
@app.route('/v1/departments/add', methods=['POST'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def createDepartment():
    app.logger.info("create department")
    if request.method == 'POST':
        department = Department(name=request.args.get('name'),
                                descripton=request.args.get('description'))
        session.add(department)
        session.commit()
        return jsonify({'message':'department has been successfully created'})


# view all departments
@app.route('/v1/departments/all', methods=['GET'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def viewAllDepartments():
    departments = session.query(Department).all()
    if request.method == 'GET':
        return jsonify(departments = [i.serialize for i in departments])


''' editing, deleting, updating and getting employees '''

# view and modify department
@app.route('/v1/employees/<int:id>', methods=['GET','PUT','DELETE'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def editEmployee(id):
    app.logger.info('editing employee')
    emp = session.query(Employee).filter_by(id=id).one()
    # view selected employee
    if request.method == 'GET':
        return jsonify(emp=emp.serialize)
    # updating employee
    if request.method == 'PUT':
        if request.args.get('firstName'):
            emp.firstName = request.args.get('firstName')
        if request.args.get('lastName'):
            emp.lastName = request.args.get('lastName')
        if request.args.get('middleName'):
            emp.middleName = request.args.get('middleName')
        if request.args.get('birthdate'):
            emp.birthdate = request.args.get('birthdate')
        if request.args.get('email'):
            emp.email = request.args.get('email')
        if request.args.get('ssn'):
            emp.ssn = request.args.get('ssn')
        if request.args.get('gender'):
            emp.gender = request.args.get('gender')
        if request.args.get('homePhone'):
            emp.homePhone = request.args.get('homePhone')
        if request.args.get('cellPhone'):
            emp.cellPhone = request.args.get('cellPhone')
        if request.args.get('address'):
            emp.address = request.args.get('address')
        if request.args.get('city'):
            emp.city = request.args.get('city')
        if request.args.get('State'):
            emp.State = request.args.get('State')
        if request.args.get('zipCode'):
            emp.zipCode = request.args.get('zipCode')
        if request.args.get('hiringDate'):
            emp.hiringDate = request.args.get('hiringDate')
        if request.args.get('title'):
            emp.title = request.args.get('title')
        if request.args.get('payRate'):
            emp.payRate = request.args.get('payRate')
        if request.args.get('status'):
            emp.status = request.args.get('status')
        if request.args.get('department_id'):
            emp.department_id = request.args.get('department_id')
        session.add(emp)
        session.commit()
        return jsonify({'message':
                        'employee with name %s has been updated' %emp.firstName})
    if request.method == 'DELETE':
        # deleting department
        session.delete(emp)
        session.commit()
        return jsonify({'message':'employee has been deleted'})


# adding a new employee
@app.route('/v1/employees/add/department/<int:department_id>', methods=['POST'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def addEmployee(department_id):
    app.logger.info("create employee")
    department = session.query(Department).filter_by(id=department_id).one()
    if request.method == 'POST':
        print("department id %d" %department_id)
        firstName = request.args.get('firstName')
        lastName = request.args.get('lastName')
        middleName = request.args.get('middleName')
        birthdate = request.args.get('birthdate')
        email = request.args.get('email')
        ssn = request.args.get('ssn')
        gender = request.args.get('gender')
        homePhone = request.args.get('homePhone')
        cellPhone = request.args.get('cellPhone')
        address = request.args.get('address')
        city = request.args.get('city')
        State = request.args.get('State')
        zipCode = request.args.get('zipCode')
        emp = Employee(firstName=firstName, lastName=lastName, middleName=middleName,
                       birthdate=birthdate, email=email, ssn=ssn,
                       gender=gender, homePhone=homePhone,
                       cellPhone=cellPhone, address=address, city=city,
                       State=State, zipCode=zipCode, department=department)
        
        session.add(emp)
        session.commit()
        return jsonify({'message':'employee has been successfully created'})


# view all employee
@app.route('/v1/employees/all', methods=['GET'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def viewAllEmployees():
    employees = session.query(Employee).all()
    if request.method == 'GET':
        return jsonify(employees = [i.serialize for i in employees])


''' editing, deleting, updating and getting education '''

# view and modify education
@app.route('/v1/employees/<int:id>/education/<int:education_id>', methods=['GET','PUT','DELETE'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def editEmployeeEducation(id, education_id):
    app.logger.info('editing education')
    education = session.query(Education).filter_by(id=education_id).one()
    # view selected education
    if request.method == 'GET':
        return jsonify(education.serialize)
    # updating education
    if request.method == 'PUT':
        if request.args.get('institution'):
                education.institution = request.args.get('institution')
        if request.args.get('major'):
                education.major =request.args.get('major')
        if request.args.get('start'):
                education.start = request.args.get('start')
        if request.args.get('end'):
                education.end = request.args.get('end')
        session.add(education)
        session.commit()
        return jsonify({'message':
                        'education with name %s has been updated ' %education.institution})
    if request.method == 'DELETE':
        # deleting education
        session.delete(education)
        session.commit()
        return jsonify({'message':'education has been deleted'})


# adding education
@app.route('/v1/employees/<int:id>/education/add', methods=['POST'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def createEducation(id):
    app.logger.info("create department")
    employee = session.query(Employee).filter_by(id=id).one()
    if request.method == 'POST':
        institution = request.args.get('institution')
        major = request.args.get('major')
        start = request.args.get('start')
        end = request.args.get('end')
        education = Education(institution=institution, major=major, start=start, end=end, employee=employee)
        session.add(education)
        session.commit()
        return jsonify({'message':'education has been successfully created'})


# view all education
@app.route('/v1/employees/<int:id>/education/all', methods=['GET'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def viewAllEducation(id):
    education = session.query(Education).filter_by(employee_id=id).all()
    if request.method == 'GET':
        return jsonify(educations = [i.serialize for i in education])


''' editing, deleting, updating and getting note '''
# editing note
@app.route('/v1/employees/<int:id>/note/<int:note_id>', methods=['GET','PUT','DELETE'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def editEmployeeNote(id, note_id):
    app.logger.info('editing note')
    note = session.query(Note).filter_by(id=note_id).one()
    # view selected note
    if request.method == 'GET':
        return jsonify(note.serialize)
    # updating note
    if request.method == 'PUT':
        if request.args.get('body',''):
                note.body = request.args.get('body','')
        session.add(note)
        session.commit()
        return jsonify({'message':
                        'note has been updated '})
    if request.method == 'DELETE':
        # deleting note
        session.delete(note)
        session.commit()
        return jsonify({'message':'note has been deleted'})


# add note
@app.route('/v1/employees/<int:id>/note/add', methods=['POST'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def createNote(id):
    app.logger.info("create department")
    employee = session.query(Employee).filter_by(id=id).one()
    if request.method == 'POST':
        body = request.args.get('body')
        usr_id = g.user.id
        note = Note(body=body,user_id=usr_id,employee=employee)
        session.add(note)
        try:
            session.commit()
        except:
           session.rollback()
           raise
        finally:
           session.close()
        return jsonify({'message':'note has been successfully created'})


# view all note
@app.route('/v1/employees/<int:id>/note/all', methods=['GET'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def viewAllNote(id):
    note = session.query(Note).filter_by(employee_id=id).all()
    if request.method == 'GET':
        return jsonify(notes = [i.serialize for i in note])


''' editing, deleting, updating and getting emergency '''
# editing emergency
@app.route('/v1/employees/<int:id>/emergency/<int:emergency_id>', methods=['GET','PUT','DELETE'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def editEmployeeEmergency(id, emergency_id):
    app.logger.info('editing emergency')
    emergency = session.query(Emergency).filter_by(id=emergency_id).one()
    # view selected emergency
    if request.method == 'GET':
        return jsonify(emergency.serialize)
    # updating emergency
    if request.method == 'PUT':
        if request.args.get('firstName'):
            emergency.firstName = request.args.get('firstName')
        if request.args.get('lastName'):
            emergency.lastName = request.args.get('lastName')
        if request.args.get('homePhone'):
            emergency.homePhone = request.args.get('homePhone')
        if request.args.get('cellPhone'):
            emergency.cellPhone = request.args.get('cellPhone')
        session.add(emergency)
        session.commit()
        return jsonify({'message':
                        'emergency has been updated '})
    if request.method == 'DELETE':
        # deleting emergency
        session.delete(emergency)
        session.commit()
        return jsonify({'message':'note has been deleted'})


# adding emergency
@app.route('/v1/employees/<int:id>/emergency/add', methods=['POST'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def createEmergency(id):
    app.logger.info("create emergency")
    employee = session.query(Employee).filter_by(id=id).one()
    if request.method == 'POST':
        firstName = request.args.get('firstName')
        lastName = request.args.get('lastName')
        homePhone = request.args.get('homePhone')
        cellPhone = request.args.get('cellPhone')
        emergency = Emergency(firstName=firstName, lastName=lastName,
                              homePhone=homePhone, cellPhone=cellPhone, employee=employee)
        session.add(emergency)
        session.commit()
        return jsonify({'message':'emergency has been successfully created'})

# view all emergencies
@app.route('/v1/employees/<int:id>/emergency/all', methods=['GET'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def viewAllEmergency(id):
    emergency = session.query(Emergency).filter_by(employee_id=id).all()
    if request.method == 'GET':
        return jsonify(emergencies = [i.serialize for i in emergency])


''' editing, deleting, updating and getting training '''
# editing training
@app.route('/v1/employees/<int:id>/training/<int:training_id>', methods=['GET','PUT','DELETE'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def editEmployeeTraining(id, training_id):
    app.logger.info('editing training')
    training = session.query(Training).filter_by(id=training_id).one()
    # view selected training
    if request.method == 'GET':
        return jsonify(training.serialize)
    # updating training
    if request.method == 'PUT':
        if request.args.get('traininglist_id'):
            training.traininglist_id = request.args.get('traininglist_id')
        if request.args.get('provided'):
            training.provided = request.args.get('provided')
        if request.args.get('due'):
            training.due = request.args.get('due')
        session.add(training)
        session.commit()
        return jsonify({'message':
                        'training has been updated '})
    if request.method == 'DELETE':
        # deleting training
        session.delete(training)
        session.commit()
        return jsonify({'message':'training has been deleted'})


# adding training
@app.route('/v1/employees/<int:id>/training/add', methods=['POST'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def createTraining(id):
    app.logger.info("create training")
    employee = session.query(Employee).filter_by(id=id).one()
    if request.method == 'POST':
        traininglist_id = request.args.get('traininglist_id')
        provided = request.args.get('provided')
        due = request.args.get('due')
        training = Training(traininglist_id=traininglist_id, provided=provided,
                              due=due, employee=employee)
        session.add(training)
        try:
            session.commit()
        except:
           session.rollback()
           raise
        finally:
           session.close()
        return jsonify({'message':'training has been successfully created'})


# view all training
@app.route('/v1/employees/<int:id>/training/all', methods=['GET'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def viewAllTraining(id):
    training = session.query(Training).filter_by(employee_id=id).all()
    if request.method == 'GET':
        return jsonify(trainings = [i.serialize for i in training])


''' editing, deleting, updating and getting onboarding '''
# editing boarding
@app.route('/v1/employees/<int:id>/boarding/<int:boarding_id>', methods=['GET','PUT','DELETE'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def editEmployeeBoarding(id, boarding_id):
    app.logger.info('editing boarding task')
    boarding = session.query(Onboarding).filter_by(id=boarding_id).one()
    # view selected boarding
    if request.method == 'GET':
        return jsonify(boarding.serialize)
    # updating boarding
    if request.method == 'PUT':
        if request.args.get('onboardinglist_id'):
            boarding.onboardinglist_id = request.args.get('onboardinglist_id')
        if request.args.get('provided'):
            boarding.provided = request.args.get('provided')
        if request.args.get('expired'):
            boarding.expired = request.args.get('expired')
        session.add(boarding)
        session.commit()
        return jsonify({'message':
                        'boarding item has been updated '})
    if request.method == 'DELETE':
        # deleting boarding
        session.delete(boarding)
        session.commit()
        return jsonify({'message':'boarding has been deleted'})


# adding boarding
@app.route('/v1/employees/<int:id>/boarding/add', methods=['POST'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def createBoarding(id):
    app.logger.info("create boarding task")
    employee = session.query(Employee).filter_by(id=id).one()
    if request.method == 'POST':
        onboardinglist_id = request.args.get('onboardinglist_id')
        provided = request.args.get('provided')
        expired = request.args.get('expired')
        boarding = Onboarding(provided=provided, expired=expired,
                              onboardinglist_id=onboardinglist_id,
                              employee=employee)
        session.add(boarding)
        try:
            session.commit()
        except:
           session.rollback()
           raise
        finally:
           session.close()
        return jsonify({'message':'boarding has been successfully created'})


# view all boarding items
@app.route('/v1/employees/<int:id>/boarding/all', methods=['GET'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def viewAllBoarding(id):
    boarding = session.query(Onboarding).filter_by(employee_id=id).all()
    if request.method == 'GET':
        return jsonify(boardings = [i.serialize for i in boarding])


''' About the company'''
@app.route('/v1/company/<int:id>', methods=['GET','PUT','DELETE'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def editCompany(id):
    app.logger.info('editing boarding task')
    compnay = session.query(Company).filter_by(id=id).first()
    # view selected company
    if request.method == 'GET':
        return jsonify(compnay.serialize)
    # updating company
    if request.method == 'PUT':
        if request.args.get('name'):
            company.name = request.args.get('name')
        session.add(company)
        session.commit()
        return jsonify({'message':
                        'company name has been updated '})
    if request.method == 'DELETE':
        # deleting company
        session.delete(company)
        session.commit()
        return jsonify({'message':'company name has been deleted'})


# adding company name
@app.route('/v1/company/add', methods=['POST'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def createCompany():
    app.logger.info("create company")
    if request.method == 'POST':
        name = request.args.get('name')
        company = Company(name=name)
        session.add(company)
        session.commit()
        return jsonify({'message':'company has been successfully created'})


# view company
@app.route('/v1/company/all', methods=['GET'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def viewCompany():
    company = session.query(Company).all()
    if request.method == 'GET':
        return jsonify(company = [i.serialize for i in company])


''' About the company links'''
@app.route('/v1/company/links/<int:id>', methods=['GET','PUT','DELETE'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def editCompanyLinks(id):
    app.logger.info('editing boarding task')
    links = session.query(CompanyLinks).filter_by(id=id).one()
    # view selected department
    if request.method == 'GET':
        return jsonify(links.serialize)
    # updating department
    if request.method == 'PUT':
        if request.args.get('name'):
            links.name = request.args.get('name')
        if request.args.get('link'):
            links.link = request.args.get('link')
        session.add(links)
        session.commit()
        return jsonify({'message':
                        'company link has been updated '})
    if request.method == 'DELETE':
        # deleting department
        session.delete(links)
        session.commit()
        return jsonify({'message':'company link has been deleted'})


# adding company links
@app.route('/v1/company/links/add', methods=['POST'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def createCompanyLinks():
    app.logger.info("create company")
    if request.method == 'POST':
        name = request.args.get('name')
        link = request.args.get('link')
        companyLinks = CompanyLinks(name=name, link=link)
        session.add(companyLinks)
        session.commit()
        return jsonify({'message':'company has been successfully created'})


# view company links
@app.route('/v1/company/links/all', methods=['GET'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def viewCompanyLinks():
    companyLinks = session.query(CompanyLinks).all()
    if request.method == 'GET':
        return jsonify(companyLinks = [i.serialize for i in companyLinks])


''' list of Training and onboarding task '''
''' edit, delete, get, add '''
@app.route('/v1/company/list_of_training/<int:id>', methods=['GET','PUT','DELETE'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def editTrainingList(id):
    app.logger.info('editing training list')
    training = session.query(Traininglist).filter_by(id=id).one()
    # view selected department
    if request.method == 'GET':
        return jsonify(training.serialize)
    # updating department
    if request.method == 'PUT':
        if request.args.get('name'):
            training.name = request.args.get('name')
        if request.args.get('description'):
            training.description = request.args.get('description')
        session.add(training)
        session.commit()
        return jsonify({'message':
                        'training item has been updated '})
    if request.method == 'DELETE':
        # deleting department
        session.delete(training)
        session.commit()
        return jsonify({'message':'training item has been deleted'})


# adding training item
@app.route('/v1/company/list_of_training/add', methods=['POST'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def createTrainingItem():
    app.logger.info("create training item")
    if request.method == 'POST':
        name = request.args.get('name')
        description = request.args.get('description')
        traininglist = Traininglist(name=name, description=description)
        session.add(traininglist)
        session.commit()
        return jsonify({'message':'training item has been successfully created'})


# view company links
@app.route('/v1/company/list_of_training/all', methods=['GET'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def viewTrainingList():
    traininglist = session.query(Traininglist).all()
    if request.method == 'GET':
        return jsonify(traininglist = [i.serialize for i in traininglist])


@app.route('/v1/company/list_of_boarding/<int:id>', methods=['GET','PUT','DELETE'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def editBoardingList(id):
    app.logger.info('editing boarding list')
    boarding = session.query(Onboardinglist).filter_by(id=id).one()
    # view selected department
    if request.method == 'GET':
        return jsonify(boarding.serialize)
    # updating department
    if request.method == 'PUT':
        if request.args.get('name'):
            boarding.name = request.args.get('name')
        if request.args.get('description'):
            boarding.description = request.args.get('description')
        session.add(boarding)
        session.commit()
        return jsonify({'message':
                        'boarding item has been updated '})
    if request.method == 'DELETE':
        # deleting department
        session.delete(boarding)
        session.commit()
        return jsonify({'message':'boarding item has been deleted'})


# adding boarding item
@app.route('/v1/company/list_of_boarding/add', methods=['POST'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def createBoardingItem():
    app.logger.info("create training item")
    if request.method == 'POST':
        name = request.args.get('name')
        description = request.args.get('description')
        boarding = Onboardinglist(name=name, description=description)
        session.add(boarding)
        session.commit()
        return jsonify({'message':'boarding item has been successfully created'})


# view boarding items
@app.route('/v1/company/list_of_boarding/all', methods=['GET'])
@auth.login_required
@ratelimit(limit=300, per=60*15)
def viewBoardingList():
    onboardinglist = session.query(Onboardinglist).all()
    if request.method == 'GET':
        return jsonify(onboardinglist = [i.serialize for i in onboardinglist])


''' Patient Side '''



if __name__ == '__main__':
    app.debug = True
    app.config['SECRET_KEY'] = ''.join(random.choice(string.ascii_uppercase +
                                                     string.digits)
                                       for x in range(32))
    app.run(host='0.0.0.0', port=5000)
