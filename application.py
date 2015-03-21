#!us/bin/python

import sqlite3, os, httplib2, json, requests
import string, random, md5, hashlib
from datetime import datetime, timedelta

from flask import Flask, url_for, session, g, redirect, make_response, Response
from flask import render_template, request, abort, flash
from contextlib import closing
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from flask import flash
from flask.ext.script import Manager
from flask.ext.migrate import Migrate, MigrateCommand

#os.putenv('FLASK_APPLICATION_SETTINGS', 'settings.cfg')
app = Flask(__name__)
app.config.from_envvar('FLASK_APPLICATION_SETTINGS')
#app.config['SQLALCHEMY_DATABSE_URI'] = 'sqlite:////database.db'
app.config.update({
    'SQLALCHEMY_DATABASE_URI': 'sqlite:///db.sqlite',
})
db = SQLAlchemy(app)
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

def init_db():
	db = SQLAlchemy(app)
	db.create_all()


class User(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(64), unique=True, nullable=False)
	password = db.Column(db.String(64), unique=True, nullable=False)
	name = db.Column(db.String(64), nullable=False)
	email = db.Column(db.String(120), unique=True, nullable=False)
	telephone = db.Column(db.String(16), nullable=False)
	
	def __init__(self, username, password, name, email, telephone):
		self.username = username
		self.password = password
		self.name = name
		self.email = email
		self.telephone = telephone

	def __repr__(self):
		return '<id: %d, Username: %s, Name: %s>' %(self.id, self.username, self.name)


class Menu(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	title = db.Column(db.String(64), unique=True, nullable=False)
	price = db.Column(db.Float, nullable=False)

	def __init__(self, title, price):
		self.title = title
		self.price = price
	def __repr__(self):
		return '<Title: %s, Price: %s' % (self.title, self.price)


class Order(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	datetime = db.Column(db.DateTime, nullable=False)
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
	menu_id = db.Column(db.Integer, db.ForeignKey('menu.id'))
	db.UniqueConstraint('datetime', 'user_id')

	def __init__(self, user_id, menu_id):
		self.datetime = datetime.utcnow()
		self.user_id = user_id
		self.menu_id = menu_id

	def __repr__(self):
		return '<user_id: %d, menu_id: %d' % (self.user_id, self.menu_id)

class Client(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(40))
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
	client_id = db.Column(db.String(32), unique=True, nullable=False)
	client_secret = db.Column(db.String(64), unique=True, nullable=False)

	def __init__(self, user_id):
		self.user_id = user_id
		self.username = User.query.filter_by(id=user_id).first().username
		self.client_id = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(32))
		self.client_secret = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(32))

	def __repr__(self):
		return 'id: %d, user_id: %d, user_name: %s, id: %s, secret: %s' % (self.id, self.user_id, self.username, self.client_id, self.client_secret)

class Token(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	client_id = db.Column(db.Integer, db.ForeignKey('client.id')) # unique=True
	code = db.Column(db.String(128), unique=True, nullable=False)
	access_token = db.Column(db.String(255), unique=True)
	refresh_token = db.Column(db.String(255), unique=True)
	token_expires = db.Column(db.DateTime)
	code_expires = db.Column(db.DateTime, nullable=False)
	redirect_uri = db.Column(db.String(512))

	def __init__(self, client_id, client_id_str, redirect_uri = None):
		self.client_id = client_id
		now = datetime.utcnow()
		self.code_expires = now + timedelta(minutes = 5)
		self.code = hashlib.sha224(client_id_str + now.strftime(DATE_FORMAT)).hexdigest()
		self.redirect_uri = redirect_uri

	def __repr__(self):
		return 'id: %d, client_id: %d, code: %s, expires: %s, redirect_uri: %s, access: %s, refresh:%s' % (self.id, self.client_id, self.code, self.code_expires.strftime(DATE_FORMAT), self.redirect_uri, self.access_token, self.refresh_token)

	def code_expired(self):
		return not (self.code_expires - datetime.utcnow() > timedelta(seconds=0))

	def token_expired(self):
		return not (self.token_expires - datetime.utcnow() > timedelta(seconds=0))

	def create_tokens(self):
		now = datetime.utcnow()
		self.token_expires = now + timedelta(minutes = 4)
		self.access_token = hashlib.sha224('access' + self.code + now.strftime(DATE_FORMAT)).hexdigest()
		self.refresh_token = hashlib.sha224('refresh' + self.code + now.strftime(DATE_FORMAT)).hexdigest()
		return (self.access_token, self.refresh_token, self.token_expires.strftime(DATE_FORMAT))

# Code request and response
@app.route('/oauth', methods=['GET', 'POST'])
def oauth():
	user = current_user()
	if request.method == 'GET' and user is not None:
		response_type = request.args.get('response_type')
		client_id = request.args.get('client_id')
		redirect_uri = request.args.get('redirect_uri')
		#print request
		if response_type is not None and response_type == 'code':
			if client_id is not None:
				client = Client.query.filter_by(client_id=client_id).first()
				if client.user_id == user.id:
					if client is not None:
						token = Token.query.filter_by(client_id=client.id).first()
						if token is None:
							token = Token(client.id, client_id, redirect_uri)
							db.session.add(token)
							db.session.commit()
						elif token.code_expired():
							db.session.delete(token)
							token = Token(client.id, client_id, redirect_uri)
							db.session.add(token)
							db.session.commit()
						if redirect_uri is not None:
							return redirect(redirect_uri + '?code=' + token.code)
						else:
							return json.dumps({'code' : token.code})
				else:
					return 'Incorrect credentials: mismatch of client and user'
			return 'Inocrrect credentials: client_id is required'
		else:
			return 'Incorrect response_type: value of response_type must be code'
	if request.method == 'GET' and user is None:
		return render_template('auth.html', url=request.url, method='POST')
	if request.method == 'POST':
		username = request.form.get('username')
		password = request.form.get('password')
		user = User.query.filter_by(username=username, password=password).first()
		if not user:
			return 'Access denied: incorrect credentials'
		else:
			session['id'] = user.id
		return redirect(request.url)

# Request and response access token
@app.route('/oauth/token', methods = ['POST'])
def oauth_token():
	#user = current_user()
	#if user == None: abort(401)
	if request.method == 'POST':
		data = request.json
		print 'here1'
		grant_type = data.get('grant_type')
		print 'here'
		if grant_type == 'refresh_token':
			refresh_token = data.get('refresh_token')
			if refresh_token is None:
				result = 'invalid request'
			else:
				result = refresh_access_token(refresh_token)
		elif grant_type == 'authorization_code':
			client_id = data.get('client_id')
			client_secret = data.get('client_secret')
			code = data.get('code')
			redirect_uri = data.get('redirect_uri')
			if code is None or client_id is None or client_secret is None:
				result = 'invalid request'
			else:
				result = issue_access_token(code, client_id, client_secret, redirect_uri)
		else:
			result = 'unsupported_grant_type'
		return result

def refresh_access_token(refresh_token):
	token = Token.query.filter_by(refresh_token=refresh_token).first()
	if token is None:
		result = 'invalid_grant (incorrect refresh_token)'
	else:
		acc, ref, exp = token.create_tokens()
		db.session.commit()
		result = json.dumps({'access_token' : acc, 'refresh_token' : ref, 'expires' : exp, 'token_type' : 'bearer'})
	return result

def issue_access_token(code, client_id, client_secret, redirect_uri):
	#client = Client.query.filter_by(user_id=user.id).first()
	client = Client.query.filter_by(client_id=client_id).first()
	if client is not None:
		#if client.client_id != client_id or client.client_secret != client_secret:
		if client.client_secret != client_secret:
			return 'invalid_client'
		token = Token.query.filter_by(client_id=client.id).first()
		if token is not None:
			if token.code != code:
				return 'invalid_grant (incorrect code)'
			elif token.code_expired():
				return 'invalid_grant (code has expired)'
			elif token.access_token != None:
				db.session.delete(token)
				db.session.commit()
				return 'invalid_grant (reuse of code)'
			else:
				if token.redirect_uri is not None:
					if token.redirect_uri != redirect_uri:
						return 'invalid_grant (uri does not match)'
				else: # IT'S OKAY
					acc, ref, exp = token.create_tokens()
					db.session.commit()
					return json.dumps({'access_token' : acc, 'refresh_token' : ref, 'expires' : exp, 'token_type' : 'bearer'})
		else:
			return 'invalid_grant (token was not founded)'
	else:
		return 'invalid_client'


# Private
@app.route('/uinfo')
def uinfo():
	access_token = request.headers.get('Authorization')
	if access_token is None:
		result = 'invalid_request'
	else:
		token = Token.query.filter_by(access_token=access_token).first()
		if token is None:
			result = 'invalid_grant'
		elif token.token_expired():
			result = 'invalid_grant (access_token expired)'
		else:
			client = Client.query.filter_by(id=token.client_id).first()
			user = User.query.filter_by(id=client.user_id).first()
			data = {'username' : user.username, 'name' : user.name, 'email' : user.email, 'telephone' : user.telephone}
			result = json.dumps(data)
	return result

# Private
@app.route('/orders', methods = ['GET'])
@app.route('/orders/<int:order_id>', methods = ['GET'])
def orders(order_id=None):
	access_token = request.headers.get('Authorization')
	if access_token is None:
		result = 'invalid_request'
	else:
		token = Token.query.filter_by(access_token=access_token).first()
		if token is None:
			result = 'invalid_grant'
		elif token.token_expired():
			result = 'invalid_grant (access_token expired)'
		else:
			client = Client.query.filter_by(id=token.client_id).first()
			user = User.query.filter_by(id=client.user_id).first()
			data = {}
			if order_id is None:
				order_list = Order.query.filter_by(user_id=user.id)
				if order_list is None:
					result = 'no any orders'
				else:
					page_id = request.args.get('page_id')
					page_num = request.args.get('page_num')
					if page_id is not None and page_num is not None:
						i = 0
						page_id = int(page_id)
						page_num = int(page_num)
						for order in order_list:
							if i >= page_id and i <= page_num:
								menu_item = Menu.query.filter_by(id=order.menu_id).first()
								data[str(order.id)] = {'datetime' : order.datetime.strftime(DATE_FORMAT), 'item' : menu_item.title, 'price' : menu_item.price}
							i += 1
					else:
						for order in order_list:
							menu_item = Menu.query.filter_by(id=order.menu_id).first()
							data[str(order.id)] = {'datetime' : order.datetime.strftime(DATE_FORMAT), 'item' : menu_item.title, 'price' : menu_item.price}
					result = data
			else:
				order = Order.query.filter_by(user_id=user.id, id=order_id).first()
				if order is None:
					result = 'no any orders'
				else:
					menu_item = Menu.query.filter_by(id=order.menu_id).first()
					data[str(order.id)] = {'datetime' : order.datetime.strftime(DATE_FORMAT), 'item' : menu_item.title, 'price' : menu_item.price}
					result = data
		result = json.dumps(result)
	return result

# Public
@app.route('/menu_list/', methods=['POST', 'GET'])
@app.route('/menu_list/<int:menu_id>', methods=['POST', 'GET'])
def menu_list(menu_id=None):
	if request.method == 'GET':
		menu_dict = {}
		if menu_id is None:
			menu_list = Menu.query.all()
			if len(menu_list) == 0:
				menu_dict = 'menu is empty'
			else:
				page_id = request.args.get('page_id')
				page_num = request.args.get('page_num')
				if page_num is not None and page_id is not None:
					page_id = int(page_id)
					page_num = int(page_num)
					i = 0
					for item in menu_list:
						if i >= page_id and i <= page_num:	
							menu_dict[item.id] = [item.title, item.price]
						i += 1
				else:
					for item in menu_list: menu_dict[item.id] = [item.title, item.price]
		else:
			item = Menu.query.filter_by(id=menu_id).first()
			if item is None:
				menu_dict = 'no any menu item with id = %d' % menu_id
			else:
				menu_dict[item.id] = [item.title, item.price]	
		data = json.dumps(menu_dict)
	#resp = make_response(render_template('menulist.html', data=data), 200)
	#return resp
	#return render_template('menulist.html', data=data)
	return data

@app.route('/registration', methods=['POST', 'GET'])
def registration():
	if request.method == 'POST':
		username = request.form.get('username')
		password = request.form.get('password')
		name = request.form.get('name')
		email = request.form.get('email')
		tel= request.form.get('tel')
		cclient = request.form.get('cclient')
		db.session.add(User(username, password, name, email, tel))
		db.session.commit()
		if cclient is not None:
			user = User.query.filter_by(username=username).first()
			db.session.add(Client(user.id))
			db.session.commit()
		return render_template('home.html', user=None)
	return render_template('register.html')

@app.route('/', methods=['GET', 'POST'])
def home():
	if request.method == 'POST':
		username = request.form.get('username')
		password = request.form.get('password')
		user = User.query.filter_by(username=username, password=password).first()
		if not user:
			error = 'Invalid credentials!'
			flash('Invalid credentials!')
		else:
			session['id'] = user.id
		return redirect('/')
	user = current_user()
	data_list = None
	client = None
	if user is not None:
		client = Client.query.filter_by(user_id=user.id).first()
		order_list = Order.query.filter_by(user_id=user.id)
		if order_list is not None:
			data_list = []
			for order in order_list:
				menu_item = Menu.query.filter_by(id=order.menu_id).first()
				data_list.append({'datetime' : order.datetime.strftime(DATE_FORMAT), 'item' : menu_item.title, 'price' : menu_item.price})
	return render_template('home.html', user=user, data_list=data_list, client=client)

@app.route('/logout', methods=['POST'])
def logout():
	if request.method == 'POST':
		request.form.get('logout')
		session['id'] = ''
	return redirect('/')#render_template('home.html', user=None)

def current_user():
	if 'id' in session:
		uid = session['id']
		return User.query.get(uid)
	return None

if __name__=='__main__':
	db.create_all()
	app.run()
