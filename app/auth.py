import functools
import random
import flask
from . import utils

from email.message import EmailMessage
import smtplib

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from app.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/activate', methods=('GET', 'POST'))
def activate():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
        
        if request.method == 'GET':  # especificar metodo
            # numero del link de activacion
            number = request.args['auth'] # number va en el challenge de la tabla activation de la db
            
            db = get_db() # creamos conexion
            # creamos cursor que almacena ejecuciones de sentencias

            # buscamos usuarios no activados
            attempt = db.execute(
                'select * from activationlink where challenge=? and state=?', (number, utils.U_UNCONFIRMED)
            ).fetchone()

            # si existe actualizamos a activado y luego creamos user en tabla user de la db
            if attempt is not None:
                db.execute(
                    'update activationlink set state=? where id=?', (utils.U_CONFIRMED, attempt['id'])
                )
                db.execute(
                    'insert into user (username, password, salt, email) values(?,?,?,?)', (attempt['username'], attempt['password'], attempt['salt'], attempt['email'])
                )
                db.commit()

        return redirect(url_for('auth.login'))
    except Exception as e:
        print(e)
        return redirect(url_for('auth.login'))


@bp.route('/register', methods=('GET', 'POST'))
def register():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
      
        if request.method == 'POST':

            # guardamos los campos del formulario registro mediante request 
            username = request.form['username']
            password = request.form['password']
            email = request.form['email']
            
            db = get_db()
            error = None

            # verificamos que los campos no esten vacios y se ingresen datos validos
            if not username:
                error = 'Username is required.'
                flash(error)
                return render_template('auth/register.html')
            
            if not utils.isUsernameValid(username):
                error = "Username should be alphanumeric plus '.','_','-'"
                flash(error)
                return render_template('auth/register.html')

            if not password:
                error = 'Password is required.'
                flash(error)
                return render_template('auth/register.html')

            # verificamos que el usuario no este registrado
            if db.execute('select * from user where username=?', (username,)).fetchone() is not None:
                error = 'User {} is already registered.'.format(username)
                flash(error)
                return render_template('auth/register.html')
            
            if (not email or (not utils.isEmailValid(email))):
                error =  'Email address invalid.'
                flash(error)
                return render_template('auth/register.html')
            
            # verificamos que el correo no este registrado
            if db.execute('SELECT * FROM user WHERE email = ?', (email,)).fetchone() is not None:
                error =  'Email {} is already registered.'.format(email)
                flash(error)
                return render_template('auth/register.html')
            
            # verificamos que la contraseña sea segura
            if (not utils.isPasswordValid(password)):
                error = 'Password should contain at least a lowercase letter, an uppercase letter and a number with 8 characters long'
                flash(error)
                return render_template('auth/register.html')

            # severa encriptacion de la contraseña, se genera numero de activacion
            salt = hex(random.getrandbits(128))[2:]
            hashP = generate_password_hash(password + salt)
            number = hex(random.getrandbits(512))[2:]

            # se crea registro de link de activacion
            db.execute(
                'insert into activationlink(challenge,state,username,password,salt,email) values(?,?,?,?,?,?)',
                (number, utils.U_UNCONFIRMED, username, hashP, salt, email)
            )
            db.commit()

            # capturamos credenciales para luego enviar email
            credentials = db.execute(
                'Select user,password from credentials where name=?', (utils.EMAIL_APP,)
            ).fetchone()

            content = 'Hello there, to activate your account, please click on this link ' + flask.url_for('auth.activate', _external=True) + '?auth=' + number
            
            # verificar esta funcion
            send_email(credentials, receiver=email, subject='Activate your account', message=content)
            
            flash('Please check in your registered email to activate your account')
            return render_template('auth/login.html') 

        return render_template('auth/register.html') 
    except Exception as e:
        print(e)
        return render_template('auth/register.html')

    
@bp.route('/confirm', methods=('GET', 'POST'))
def confirm():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))

        if request.method == 'POST': 
            password = request.form['password']
            password1 = request.form['password1']
            authid = request.form['authid']

            if not authid:
                flash('Invalid')
                return render_template('auth/forgot.html')

            if not password:
                flash('Password required')
                return render_template('auth/change.html', number=authid)

            if not password1:
                flash('Password confirmation required')
                return render_template('auth/change.html', number=authid)

            # verificamos si las contrañesas son iguales para habilitar cambio
            if password1 != password:
                flash('Both values should be the same')
                return render_template('auth/change.html', number=authid)

            if not utils.isPasswordValid(password):
                error = 'Password should contain at least a lowercase letter, an uppercase letter and a number with 8 characters long.'
                flash(error)
                return render_template('auth/change.html', number=authid)

            db = get_db()

            # Verificar esta sentencia
            attempt = db.execute(
                'select * from forgotlink where challenge=? and state=?', (authid, utils.F_ACTIVE)
            ).fetchone()
            
            if attempt is not None:
                db.execute(
                    'update forgotlink set state=? where id=?', (utils.F_INACTIVE, attempt['id'])
                )
                salt = hex(random.getrandbits(128))[2:]
                hashP = generate_password_hash(password + salt) 

                ## verificar esta sentencia  
                db.execute(
                    'update user set password=?,salt=? where id=?', (hashP, salt, attempt['userid'])
                )
                db.commit()
                return redirect(url_for('auth.login'))
            else:
                flash('Invalid')
                return render_template('auth/forgot.html')

        return render_template('auth/change.html')
    except:
        return render_template('auth/forgot.html')


@bp.route('/change', methods=('GET', 'POST'))
def change():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
        
        if request.method == 'GET': 
            number = request.args['auth'] 
            
            db = get_db()
            attempt = db.execute(
                'select * from forgotlink where challenge=? and state=?', (number, utils.F_ACTIVE)
            ).fetchone()
            
            if attempt is not None:
                return render_template('auth/change.html', number=number)
        
        return render_template('auth/forgot.html')
    except:
        return render_template('auth/forgot.html')


@bp.route('/forgot', methods=('GET', 'POST'))
def forgot():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
        
        if request.method == 'POST':
            email = request.form['email']
            
            if (not email or (not utils.isEmailValid(email))):
                error = 'Email Address Invalid'
                flash(error)
                return render_template('auth/forgot.html')

            db = get_db()
            user = db.execute(
                'select id from user where email=?', (email,)
            ).fetchone()

            if user is not None:
                number = hex(random.getrandbits(512))[2:]
                

                # verificar querys
                db.execute(
                    'delete from forgotlink where state=? and id=?',
                    (utils.F_INACTIVE, user['id'])
                )
                db.execute(
                    'insert into forgotlink userid=?, challenge=?, state=? values(?,?,?)',
                    (user['id'], number, utils.F_ACTIVE)
                )
                db.commit()
                
                credentials = db.execute(
                    'Select user,password from credentials where name=?',(utils.EMAIL_APP,)
                ).fetchone()
                
                content = 'Hello there, to change your password, please click on this link ' + flask.url_for('auth.change', _external=True) + '?auth=' + number
                
                send_email(credentials, receiver=email, subject='New Password', message=content)
                
                flash('Please check in your registered email')
            else:
                error = 'Email is not registered'
                flash(error)            

        return render_template('auth/forgot.html')
    except:
        return render_template('auth/forgot.html')


@bp.route('/login', methods=('GET', 'POST'))
def login():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))

        if request.method == 'GET':
            username = request.form['username']
            password = request.form['password']

            if not username:
                error = 'Username Field Required'
                flash(error)
                return render_template('auth/login.html')

            if not password:
                error = 'Password Field Required'
                flash(error)
                return render_template('auth/login.html')

            db = get_db()
            error = None
            user = db.execute(
                'SELECT * FROM user WHERE username = ?', (username,)
            ).fetchone()
            
            if username != user['username']: # verificar esta linea
                error = 'Incorrect username or password'
            elif not check_password_hash(user['password'], password + user['salt']):
                error = 'Incorrect username or password'   

            if error is None:
                session.clear()
                session['user_id'] = user['id']
                return redirect(url_for('inbox.show'))

            flash(error)

        return render_template('auth/login.html')
    except Exception as e:
        print(e)
        return render_template('auth/login.html')
        

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('id') # verificar este linea

    if user_id is None:
        g.user = None
    else:
        # verificar esta sentencia
        g.user = get_db().execute(
            'select * from user where id=?', (user_id,)
        ).fetchone()

        
@bp.route('/logout')
def logout():
    session.pop('id', None) # verificar esta linea
    return redirect(url_for('auth.login'))


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)
    return wrapped_view


def send_email(credentials, receiver, subject, message):
    # Create Email
    email = EmailMessage()
    email["From"] = credentials['user']
    email["To"] = receiver
    email["Subject"] = subject
    email.set_content(message)

    # Send Email
    smtp = smtplib.SMTP("smtp-mail.outlook.com", port=587)
    smtp.starttls()
    smtp.login(credentials['user'], credentials['password'])
    smtp.sendmail(credentials['user'], receiver, email.as_string())
    smtp.quit()