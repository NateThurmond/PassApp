from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime, ForeignKey, func
)
from sqlalchemy.orm import declarative_base, Session, relationship
from sqlalchemy.dialects.sqlite import BLOB
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta
import uuid
import secrets

Base = declarative_base()

class SampleTable(Base):
    __tablename__ = 'SampleTable'
    id = Column(Integer, primary_key=True)
    value = Column(String, nullable=False)

class PassAppUsers(Base):
    __tablename__ = 'PassAppUsers'
    id = Column(Integer, primary_key=True)
    entropyId = Column(String, nullable=False, unique=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, nullable=False, unique=True)
    useremail = Column(String, nullable=False, unique=True)
    pass_hash = Column(String, nullable=False)  # Should be bcrypt/argon2 hash sent from client-side
    salt = Column(String, nullable=False)
    login_attempts = Column(Integer, default=0)
    last_login_attempt = Column(DateTime)
    created_on = Column(DateTime, nullable=False, default=func.now())
    updated_on = Column(DateTime, nullable=False, default=func.now(), onupdate=func.now())

    sessions = relationship("PassAppSessions", back_populates="user")

class PassAppSessions(Base):
    __tablename__ = 'PassAppSessions'
    id = Column(Integer, primary_key=True)
    session_uuid = Column(String, nullable=False, unique=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(Integer, ForeignKey('PassAppUsers.id'), nullable=False)
    created_on = Column(DateTime, nullable=False, default=func.now())
    last_accessed = Column(DateTime, nullable=False, default=func.now())
    expires_on = Column(DateTime, nullable=False)
    ip_address = Column(String)

    user = relationship("PassAppUsers", back_populates="sessions")

class PassAppDB:
    def __init__(self, db_path='sqlite:///passApp.db'):
        self.engine = create_engine(db_path, echo=False)
        self._create_table()

    def _create_table(self):
        Base.metadata.create_all(self.engine)

    def is_login_valid(self, submitted_hash, stored_hash):
        return submitted_hash == stored_hash

    def add_user(self, username, useremail, pass_hash, salt):
        new_user = PassAppUsers(
            username=username,
            useremail=useremail,
            pass_hash=pass_hash,
            salt=salt,
            entropyId=secrets.token_urlsafe(32)
        )
        with Session(self.engine) as session:
            try:
                session.add(new_user)
                session.commit()
                return True
            except IntegrityError:
                session.rollback()
                return False

    def check_user_uniqueness(self, username, useremail):
        with Session(self.engine) as session:
            user = session.query(PassAppUsers).filter(
                (PassAppUsers.username == username) |
                (PassAppUsers.useremail == useremail)
            ).first()
            return user is None

    def validate_login(self, username, posted_pass_hash, ip):
        with Session(self.engine) as session:
            user = session.query(PassAppUsers).filter_by(username=username).first()
            if not user:
                return None

            now = datetime.now()
            user.last_login_attempt = now

            if user.login_attempts >= 5:
                session.commit()
                return None  # Block login after too many attempts

            if not self.is_login_valid(posted_pass_hash, user.pass_hash):
                user.login_attempts += 1
                session.commit()
                return None

            user.login_attempts = 0  # Reset on success

            # Create session UUID
            new_session = PassAppSessions(
                user=user,
                expires_on=now + timedelta(hours=1),
                ip_address=ip
            )
            session.add(new_session)
            session.commit()
            return new_session.session_uuid

    def get_user_by_session(self, session_uuid):
        now = datetime.now()
        with Session(self.engine) as session:
            s = session.query(PassAppSessions).filter_by(session_uuid=session_uuid).first()
            if not s or s.expires_on < now:
                return None
            s.last_accessed = now
            session.commit()
            return s.user

    def populate_sample(self):
        with Session(self.engine) as session:
            session.query(SampleTable).delete()  # Clear existing
            session.add(SampleTable(value='hello world'))
            session.commit()

    def get_sample_value(self):
        with Session(self.engine) as session:
            row = session.query(SampleTable).first()
            return row.value if row else None
