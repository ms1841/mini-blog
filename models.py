from init import db, app


class Blog(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(50))
    entry = db.Column(db.String(10000))

db.create_all(app=app)
