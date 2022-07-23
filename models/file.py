from db import db


class File(db.Model):
    __tablename__ = 'files'

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(80))
    public_id = db.Column(db.String(50), unique=True)

    def __init__(self, filename, public_id):
        self.filename = filename
        self.public_id = public_id

    @classmethod
    def find_by_filename(cls, filename):
        return cls.query.filter_by(filename=filename).first()

    @classmethod
    def find_by_public_id(cls, public_id):
        return cls.query.filter_by(public_id=public_id).first()

    @classmethod
    def find_all_files(cls):
        return cls.query.all()

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()
