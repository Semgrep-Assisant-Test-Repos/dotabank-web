from flask import render_template, abort, send_file
from app import app, db
from app.models import Stats, UGCFile
from app.replays.models import Replay
from app.replays.forms import SearchForm
from flask.ext.login import current_user
import requests
import os


@app.context_processor
def inject_search_form():
    """ Inject a search form instance into Jinja2 - for the site-wide search box's CSRF protection. """
    return dict(search_form=SearchForm())


# Routes
@app.route('/')
def index():
    """ Home page. Has a jumbotron explaining the site, with a search-box call to action. Lists latest addeed replays,
    latest archived replays, some public stats about the state of the site. """
    last_added_replays = Replay.query.order_by(Replay.added_to_site_time.desc()).limit(app.config["LATEST_REPLAYS_LIMIT"]).all()
    last_archived_replays = Replay.query.filter(Replay.state == "ARCHIVED").order_by(Replay.dl_done_time.desc()).limit(app.config["LATEST_REPLAYS_LIMIT"]).all()

    stats = Stats()

    search_form = SearchForm()

    return render_template("dotabank.html",
                           last_added_replays=last_added_replays,
                           last_archived_replays=last_archived_replays,
                           stats=stats,
                           search_form=search_form)


@app.route('/ugcfile/<int:_id>')
def ugcfile(_id):
    _ugcfile = UGCFile.query.filter(UGCFile.id == _id).first()
    if not _ugcfile:
        _ugcfile = UGCFile(_id)

        # Only save if we actually have data
        if _ugcfile.url:
            db.session.add(_ugcfile)
            db.session.commit()

    # If we already have on disk, serve it.
    if os.path.exists(_ugcfile.local_uri):
        return send_file(_ugcfile.local_uri)

    # Otherwise fetch, save to disk, then serve it.
    if _ugcfile.url:
        with open(_ugcfile.local_uri, 'w') as f:
            req = requests.get(_ugcfile.url, stream=True)
            if req.ok:
                for block in req.iter_content(1024):
                    f.write(block)
                return send_file(_ugcfile.local_uri)

    # If all of the above fails, throw 404.
    abort(404)


@app.route('/static/images/heroes/<hero_name>.png')
def hero_image(hero_name):
    """ Attempts to serve a hero's image from the filesystem, downloading and saving the file if possible.
    The file should be served by nginx, but will fall back to this code if nginx throws 404. """
    local_path = os.path.join(
        app.static_folder,
        "images/heroes/{}.png".format(hero_name)
    )
    volvo_path = "http://media.steampowered.com/apps/dota2/images/heroes/{}_full.png".format(hero_name)

    # If we already have on disk, serve it.
    if os.path.exists(local_path):
        return send_file(local_path)

    # Otherwise fetch, save to disk, then serve it.
    with open(local_path, 'w') as f:
        req = requests.get(volvo_path, stream=True)
        if req.ok:
            for block in req.iter_content(1024):
                f.write(block)
            return send_file(local_path)

    # If all of the above fails, throw 404.
    abort(404)


@app.route('/static/images/items/<item_filename>')
def item_icon(item_filename):
    """ Attempts to serve an item's image from the filesystem, downloading and saving the file if possible.
    The file should be served by nginx, but will fall back to this code if nginx throws 404. """
    local_path = os.path.join(
        app.static_folder,
        "images/items/{}".format(item_filename)
    )
    volvo_path = "http://media.steampowered.com/apps/dota2/images/items/{}".format(item_filename)

    # If we already have on disk, serve it.
    if os.path.exists(local_path):
        return send_file(local_path)

    # Otherwise fetch, save to disk, then serve it.
    with open(local_path, 'w') as f:
        req = requests.get(volvo_path, stream=True)
        if req.ok:
            for block in req.iter_content(1024):
                f.write(block)
            return send_file(local_path)

    # If all of the above fails, throw 404.
    abort(404)


@app.route("/privacy/")
def privacy():
    """ Our privacy policy. """
    return render_template("privacy.html")


@app.route("/tos/")
def tos():
    """ Our terms of service. """
    return render_template("tos.html")


@app.route("/about/")
def about():
    """ Our about-us page. """
    return render_template("about.html")


@app.errorhandler(401)  # Unauthorized
@app.errorhandler(403)  # Forbidden
@app.errorhandler(404)  # > Missing middle!
@app.errorhandler(500)  # Internal server error.
# @app.errorhandler(Exception)  # Internal server error.
def internalerror(error):
    """ Custom error page, will catch 401, 403, 404, and 500, and output a friendly error message. """
    try:
        if error.code == 401:
            error.description = "I'm sorry Dave, I'm afraid I can't do that.  Try logging in."
        elif error.code == 403:
            if current_user.is_authenticated():
                error.description = "I'm sorry {{ current_user.name }}, I'm afraid I can't do that.  You do not have access to this resource.</p>"
            else:
                # Shouldn't output 403 unless the user is logged in.
                error.description = "Hacker."
    except AttributeError:
        # Rollback the session
        db.session.rollback()

        # E500's don't populate the error object, so we do that here.
        error.code = 500
        error.name = "Internal Server Error"
        error.description = "Whoops! Something went wrong server-side.  Details of the problem has been sent to the Dotabank team for investigation."

    # Render the custom error page.
    return render_template("error.html", error=error, title=error.name), error.code
