import httplib2
import json
import requests
import httplib2
import random
import string
from flask import Flask, render_template, request, flash, redirect
from flask import jsonify, url_for
from databse_setup import Base, Bikes, Types, User
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from flask import session as login_session
from flask import make_response
from functools import wraps
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "bikesmenu"
engine = create_engine('sqlite:///Biketypes.db',
                       connect_args={'check_same_thread': False}, echo=True)
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "bikesmenu"
engine = create_engine('sqlite:///Biketypes.db',
                       connect_args={'check_same_thread': False}, echo=True)
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# create a state token to prevent request forgery.
# store it in the session for later validation.


@app.route('/category/<int:category_id>/menu/JSON')
def categoryMenuJSON(category_id):
    category = session.query(Bikes).filter_by(id=category_id).one()
    items = session.query(Types).filter_by(
       category_id=category_id).all()
    return jsonify(Types=[i.serialize for i in items])


@app.route('/category/<int:category_id>/menu/<int:menu_id>/JSON')
def modelJSON(category_id, menu_id):
    types = session.query(Types).filter_by(id=menu_id).one()
    return jsonify(types=types.serialize)


@app.route('/category/JSON')
def categoriesJSON():
    categories = session.query(Bikes).all()
    return jsonify(categories=[r.serialize for r in categories])


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(
                    string.ascii_uppercase +
                    string.digits) for x in xrange(32))
    login_session['state'] = state
    # return "Current Session state is %s" %login_session['state']
    return render_template('login.html', STATE=state)


# Show all category
@app.route('/')
@app.route('/category/')
def showBikes():
    categories = session.query(Bikes).all()
    model = session.query(Types).order_by(Types.id.desc()).limit(3)
    if 'username' not in login_session:
        return render_template('public_category.html', categories=categories)
    else:
        return render_template('category.html', categories=categories)

    # return "This page will show all my Bike categories"


# Create a new Bike category
@app.route('/category/new/', methods=['GET', 'POST'])
def newBikes():
    if request.method == 'POST':
        if 'user_id' not in login_session and 'email' in login_session:
            login_session['user_id'] = getUserId(login_session['email'])
        newBikes = Bikes(name=request.form['name'],
                         user_id=login_session['user_id'])
        session.add(newBikes)
        session.commit()
        return redirect(url_for('showBikes'))
    else:
        return render_template('newcategory.html')
    # return "This page will be for making a new Bikes category"

# Edit a category


@app.route('/category/<int:category_id>/edit/', methods=['GET', 'POST'])
def editBikes(category_id):
    editedcategory = session.query(
        Bikes).filter_by(id=category_id).one()
    if 'username' in login_session:
        if editedcategory.user_id == login_session['user_id']:
            if request.method == 'POST':
                if request.form['name']:
                    editedcategory.name = request.form['name']
                    return redirect(url_for('showBikes'))
            else:
                return render_template(
                    'editcategory.html', category=editedcategory)
        else:
            flash("You are not authorized.......")
            return redirect(url_for('showBikes'))
    else:
        return redirect(url_for('/showLogin'))
# return 'This page will be for editing Bikes category %s' % category_id

# Delete a category


@app.route('/category/<int:category_id>/delete/', methods=['GET', 'POST'])
def deleteBikes(category_id):
    category_to_delete = session.query(Bikes).filter_by(id=category_id).one()
    if 'username' in login_session:
        if category_to_delete.user_id == login_session['user_id']:
            if request.method == 'POST':
                    session.delete(category_to_delete)
                    session.commit()
                    return redirect(url_for('showBikes',
                                            category_id=category_id))
            else:
                return render_template('deletecategory.html',
                                       category=category_to_delete)
        else:
            flash("You are not authorized.......")
            return redirect(url_for('showBikes'))
    else:
        return redirect(url_for('/showLogin'))
    # return 'This page will be for deleting category %s' % category_id


# Show a category menu
@app.route('/category/<int:category_id>/')
@app.route('/category/<int:category_id>/menu/')
def showModels(category_id):
    category = session.query(Bikes).filter_by(id=category_id).one()
    models = session.query(Types).filter_by(category_id=category_id).all()
    if 'username' not in login_session:
        return render_template('public_menu.html',
                               models=models, category=category)
    else:
        return render_template('menu.html', models=models,
                               category=category,
                               category_id=category_id)
    # return 'This page is the menu for category %s' % category_id

# Create a new category model


@app.route(
    '/category/<int:category_id>/menu/new/', methods=['GET', 'POST'])
def newTypes(category_id):
    category = session.query(Bikes).filter_by(id=category_id).one()
    if 'username' in login_session:
        if login_session['user_id'] == category.user_id:
            if request.method == 'POST':
                newModel = Types(name=request.form['name'],
                                 description=request.form['description'],
                                 price=request.form['price'],
                                 category_id=category_id,
                                 user_id=login_session['user_id'])
                session.add(newModel)
                session.commit()
                return redirect(url_for('showModels', category_id=category_id))
            else:
                return render_template('newcategorymodel.html',
                                       category_id=category_id,
                                       category=category)
        else:
            flash("permission denied")
            return redirect(url_for('showBikes'))
    else:
        redirect('/showLogin')

# Edit a category model


@app.route('/category/<int:category_id>/menu/<int:menu_id>/edit',
           methods=['GET', 'POST'])
def editTypes(category_id, menu_id):
    editedModel = session.query(Types).filter_by(id=menu_id).one()
    if editedModel.user_id != login_session['user_id']:
        flash("permission denied")
        return redirect(url_for('showModels', category_id=category_id))
    if request.method == 'POST':
        if request.form['name']:
            editedModel.name = request.form['name']
        if request.form['description']:
            editedModel.description = request.form['description']
        if request.form['price']:
            editedModel.price = request.form['price']
        session.add(editedModel)
        session.commit()
        return redirect(url_for('showModels', category_id=category_id))
    else:

        return render_template('editcategorymodel.html',
                               category_id=category_id,
                               menu_id=menu_id, model=editedModel)

    # return 'This page is for editing category_model %s' % menu_id

# Delete a model


@app.route('/category/<int:category_id>/menu/<int:menu_id>/delete',
           methods=['GET', 'POST'])
def deleteTypes(category_id, menu_id):
    model_to_delete = session.query(Types).filter_by(id=menu_id).one()
    if model_to_delete.user_id != login_session['user_id']:
        flash("permission denied")
        return redirect(url_for('showModels', category_id=category_id))
    if request.method == 'POST':
        session.delete(model_to_delete)
        session.commit()
        return redirect(url_for('showModels', category_id=category_id))
    else:
        return render_template('deleteCategoryModel.html',
                               model=model_to_delete,
                               category_id=category_id,
                               menu_id=menu_id)
# return "This page is for deleting Category model %s" % menu_id


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check whether the access token is valid or not.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # Alert and abort if there is an error in the access token.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # Check whether user exists or not, if not create a new user
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 200px; \
    height: 200px;border-radius: 150px;-webkit-border-radius: \
    150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'], 'success')
    print "done!"
    return output


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    # only disconnect a connected user
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = ('https://accounts.google.com/o/oauth2/revoke?token=%s'
           % access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']

        response = make_response(
            json.dumps('Successfully logged out!.'), 200)
        response.headers['Content-Type'] = 'application/json'
        flash('Successfully Logged Out!')
        return redirect(url_for('showBikes'))
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


# User helper functions
def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def createUser(login_session):
    newUser = User(
        name=login_session['username'],
        email=login_session['email'],
        picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
