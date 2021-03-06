from types import MethodType
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql.expression import ClauseElement


from .database import Base

def db_get(self, model, defaults=None, **kwargs):
    return self.query(model).filter_by(**kwargs).first()


def db_create(self, model, defaults=None, **kwargs):
    params = dict((k, v) for k, v in kwargs.items() if not isinstance(v, ClauseElement))
    params.update(defaults or {})
    instance = model(**params)
    self.add(instance)
    self.flush()
    return instance


def db_get_or_create(self, model, defaults=None, **kwargs):
    instance = self.get(model, defaults, **kwargs)
    if instance:
        return instance
    return self.create(model, defaults, **kwargs)

def init_database():
    engine = create_engine('sqlite:///cve.db')
    Session = sessionmaker(bind=engine)
    db = Session()
    db.get = MethodType(db_get, db)
    db.create = MethodType(db_create, db)
    db.get_or_create = MethodType(db_get_or_create, db)
    Base.metadata.create_all(engine)
    return db
