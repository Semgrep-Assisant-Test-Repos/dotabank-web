from flask import Flask

app = Flask(__name__)

from flask import request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import bindparam
from sqlalchemy import create_engine
from sqlalchemy import text
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import sessionmaker
from wtforms import Form
from wtforms import StringField
from wtforms import validators

db = SQLAlchemy(model_class=Base)
app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
db.init_app(app)


@app.route("/a/rout")
def insert_person() -> None:
    tainted = flask.request.get_json()
    engine = create_engine(
        "postgresql+psycopg2://scott:tiger@localhost:5432/mydatabase"
    )
    connection = engine.connect()

    Session = scoped_session(sessionmaker(bind=engine))
    session = Session()

    # ruleid: sqlalchemy-flask
    result = connection.execute(text("select username from users where " + tainted))

    result = connection.execute(
        # ruleid: sqlalchemy-flask
        sqlalchemy.sql.expression.text("select username from users where " + tainted)
    )

    # ok: sqlalchemy-flask
    session.query(MyClass).filter(f"foo={tainted}")  # runtime error

    # ok: sqlalchemy-flask
    db.session.query(MyClass).filter(f"foo={tainted}")  # runtime error

    query = text("SELECT * FROM your_table WHERE column = :value")
    # ok: sqlalchemy-flask
    result = connection.execute(query, value=tainted)

    # ok: sqlalchemy-flask
    result = connection.execute(
        "SELECT * FROM your_table WHERE column = :value", value=tainted
    )

    # ok: sqlalchemy-flask
    Blog.query.with_entities(Blog.blog_title).filter(
        Blog.blog_title.like("%" + tainted + "%")
    ).all()

    # ok: sqlalchemy-flask
    stmt = select(users_table).where(users_table.c.name == bindparam(tainted))

    t = (
        text("SELECT * FROM users WHERE id=:user_id")
        .bindparams(user=tainted)
        .columns(id=String, name=String)
    )

    # ok: sqlalchemy-flask
    connection.execute(t)

    connection.execute(
        select(users_table)
        .where(users_table.c.name == bindparam(tainted))
        # ruleid: sqlalchemy-flask
        .prefix_with(tainted)
    )

    connection.execute(
        select(users_table)
        .where(users_table.c.name == bindparam(tainted))
        # ruleid: sqlalchemy-flask
        .suffix_with(tainted)
    )

    connection.execute(
        select(users_table)
        # ruleid: sqlalchemy-flask
        .from_statement(tainted)
    )


class RegistrationForm(Form):
    username = StringField("Username", [validators.Length(min=4, max=25)])


@app.route("/register", methods=["GET", "POST"])
def register() -> None:
    form = RegistrationForm(request.form)
    if request.method == "POST" and form.validate():
        tainted = form.username.data

        engine = create_engine(
            "postgresql+psycopg2://scott:tiger@localhost:5432/mydatabase"
        )
        connection = engine.connect()

        Session = scoped_session(sessionmaker(bind=engine))
        Session()

        # ruleid: sqlalchemy-flask
        connection.execute(text("truncate " + tainted))

        user = User()
        form.populate_obj(user)

        # ruleid: sqlalchemy-flask
        connection.execute(text("truncate " + user.username))


from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import DataRequired


class MyForm(FlaskForm):
    name = StringField("name", validators=[DataRequired()])


@app.route("/submit", methods=["GET", "POST"])
def submit() -> None:
    form = MyForm()
    if form.validate_on_submit():
        # ruleid: sqlalchemy-flask
        connection.execute(text("truncate " + form.name.data))
        # ok: sqlalchemy-flask
        connection.execute(text("truncate " + form.name.label))
