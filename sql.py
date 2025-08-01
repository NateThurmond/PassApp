from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, Session

Base = declarative_base()

class SampleTable(Base):
    __tablename__ = 'SampleTable'
    id = Column(Integer, primary_key=True)
    value = Column(String, nullable=False)

class PassAppDB:
    def __init__(self, db_path='sqlite:///passApp.db'):
        self.engine = create_engine(db_path, echo=False)
        self._create_table()

    def _create_table(self):
        Base.metadata.create_all(self.engine)

    def populate_sample(self):
        with Session(self.engine) as session:
            session.query(SampleTable).delete()  # Clear existing
            session.add(SampleTable(value='hello world'))
            session.commit()

    def get_sample_value(self):
        with Session(self.engine) as session:
            row = session.query(SampleTable).first()
            return row.value if row else None
