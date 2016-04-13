import os
import base64
import flask
import bcrypt
from init import app, db
import models
import markdown
from markupsafe import Markup

entries = dict()


@app.route('/')
def index():
    # rendering 'index.html' template with jinja variable 'blogs'
    # assigned to Python object in 'blogs'

    # make a cross-site request forgery preventing token
    if 'csrf_token' not in flask.session:
        flask.session['csrf_token'] = base64.b64encode(os.urandom(32)).decode('ascii')

    # make a response that we can add a cookie to
    # this is only for our little cookie example, it isn't needed if you are using
    # sessions.
    post = models.Blog.query.all()
    if post is not None:
        for a_entry in post:
            content = Markup(markdown.markdown(a_entry.entry, output_format='html5'))
            entries[a_entry.title] = content
    resp = flask.make_response(flask.render_template('index.html', post=post, entries=entries,
                                                     csrf_token=flask.session['csrf_token']))
    return resp


# function that handles URLs of the form /post/number/
@app.route('/post')
def post():
    return flask.render_template('post.html')


@app.route('/add', methods=['POST'])
def add_post():
    if 'auth_user' not in flask.session:
        app.logger.warn('unauthorized user tried to add a post')
        flask.abort(401)
        # if flask.request.form['_csrf_token'] != flask.session['csrf_token']:
        # app.logger.debug('invalid CSRF token in blog form')
        # flask.abort(400)

    title = flask.request.form['title']
    entry = flask.request.form['text']
    # create a new post
    post = models.Blog()
    # set its properties
    post.title = title
    post.entry = entry
    # add it to the database
    db.session.add(post)
    # commit the database session
    db.session.commit()
    return flask.redirect(flask.url_for('blog_post', pid=post.id), code=303)


@app.route('/blog/<int:pid>')
def blog_post(pid):
    blog = models.Blog.query.get(pid)
    if blog is None:
        flask.abort(404)
    else:
        content = Markup(markdown.markdown(blog.entry, output_format='html5'))
        return flask.render_template('blog.html', blog=blog, content=content)


@app.route('/login')
def login_form():
    # GET request to /login - send the login form
    return flask.render_template('login.html')


@app.route('/login', methods=['POST'])
def handle_login():
    # POST request to /login = check user
    login = flask.request.form['user']
    password = flask.request.form['password']
    # do authentication
    if login == "admin" and password == app.config['ADMIN_PASSWORD']:
        # mark as authenticated and redirect to main page
        flask.session['auth_user'] = login
        return flask.render_template('index.html', login=login, entries=entries, state='good')
    if login != "admin" or password != app.config['ADMIN_PASSWORD']:
        # check to make sure each are BOTH bad inputs
        return flask.render_template('login.html', state='bad')


@app.route('/logout')
def handle_logout():
    # user wants to say goodbye, just forget about them
    del flask.session['auth_user']
    # redirect to specfied source URL, or / if none is present
    return flask.redirect(flask.request.args.get('url', '/'))


@app.errorhandler(404)
def not_found(err):
    return flask.render_template('404.html', path=flask.request.path), 404
