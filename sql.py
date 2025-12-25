from sqlalchemy import (
    create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey, func
)
from sqlalchemy.orm import declarative_base, Session, relationship
from sqlalchemy.dialects.sqlite import BLOB
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta, timezone
import uuid
import secrets
import threading
import time

Base = declarative_base()

# TO-DO: Make sure UTC is stored everywhere!

class PassAppUsers(Base):
    __tablename__ = 'PassAppUsers'
    id = Column(Integer, primary_key=True)
    entropyId = Column(String, nullable=False, unique=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, nullable=False, unique=True)
    useremail = Column(String, nullable=False, unique=True)
    salt = Column(String, nullable=False) # Stored as hex
    verifier = Column(String, nullable=False) # Stored as hex
    login_attempts = Column(Integer, default=0)
    last_login_attempt = Column(DateTime)
    created_on = Column(DateTime, nullable=False, default=func.now())
    updated_on = Column(DateTime, nullable=False, default=func.now(), onupdate=func.now())

    sessions = relationship("PassAppSessions", back_populates="user")

# TO-DO: Also to-do, perhaps implement foreign relationship but this limits username entries to a single row as well as requiring storing user_id
class shortLivedSrpStart(Base):
    __tablename__ = 'shortLivedSrpStart'
    id = Column(Integer, primary_key=True)
    entropyId = Column(String, nullable=False, unique=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, nullable=False, unique=True)
    empheralA = Column(String, nullable=False)
    empheralB = Column(String, nullable=False)
    verifier = Column(String, nullable=False) # Stored as hex
    consumed = Column(Boolean, nullable=False, default=False)
    created_on = Column(DateTime, nullable=False, default=func.now())
    updated_on = Column(DateTime, nullable=False, default=func.now(), onupdate=func.now())

class PassAppSessions(Base):
    __tablename__ = 'PassAppSessions'
    id = Column(Integer, primary_key=True)
    session_uuid = Column(String, nullable=False, unique=True, default=lambda: secrets.token_urlsafe(32))
    user_id = Column(Integer, ForeignKey('PassAppUsers.id'), nullable=False)
    created_on = Column(DateTime, nullable=False, default=func.now())
    last_accessed = Column(DateTime, nullable=False, default=func.now())
    expires_on = Column(DateTime, nullable=False)
    ip_address = Column(String)

    user = relationship("PassAppUsers", back_populates="sessions")

class KeePassVaults(Base):
    __tablename__ = 'KeePassVaults'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('PassAppUsers.id'), nullable=False)
    vault_name = Column(String, nullable=False, unique=False)
    vault_data = Column(BLOB, nullable=False)
    sha256 = Column(String, nullable=False)  # Hex SHA256 of vault_data (for versioning)
    version = Column(Integer, nullable=False, default=1)
    created_on = Column(DateTime, nullable=False, default=func.now())
    updated_on = Column(DateTime, nullable=False, default=func.now(), onupdate=func.now())

    user = relationship("PassAppUsers")

class PassAppDB:
    def __init__(self, db_path='sqlite:///passApp.db'):
        self.engine = create_engine(db_path, echo=False)
        self._create_table()
        self._start_cleanup_thread()

    def _create_table(self):
        Base.metadata.create_all(self.engine)

    '''
        Background task to clear out invalid short-lived SRPs. There are perhaps more robust implementations
        but this method is proven/reliable and runs as long as server runs and on startup.
    '''
    def _start_cleanup_thread(self):
        def cleanup_loop():
            while True:
                time.sleep(5)  # Run every N seconds
                try:
                    self.delete_expired_short_lived_srps()
                    self.delete_expired_sessions()
                except Exception as e:
                    print(f"Cleanup error: {e}")

        thread = threading.Thread(target=cleanup_loop, daemon=True)
        thread.start()

    def check_user_uniqueness(self, username, useremail):
        with Session(self.engine) as session:
            user = session.query(PassAppUsers).filter(
                (PassAppUsers.username == username) |
                (PassAppUsers.useremail == useremail)
            ).first()
            return user is None

    def check_user_name_uniqueness(self, username):
        with Session(self.engine) as session:
            user = session.query(PassAppUsers).filter(
                (PassAppUsers.username == username)
            ).first()
            return user is None

    def add_user(self, username, useremail, salt, verifier):
        new_user = PassAppUsers(
            username=username,
            useremail=useremail,
            salt=salt,
            verifier=verifier,
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

    def get_user_salt(self, username):
        with Session(self.engine) as session:
            user = session.query(PassAppUsers).filter(
                (PassAppUsers.username == username)
            ).first()
            if user:
                return {
                    "salt": user.salt,
                    "verifier": user.verifier
                }
            return None

    def store_short_lived_srp(self, username, empheralA, empheralB, verifier):
        entropyId=secrets.token_urlsafe(32)
        new_srp = shortLivedSrpStart(
            username=username,
            empheralA=empheralA,
            empheralB=empheralB,
            verifier=verifier,
            entropyId=entropyId
        )
        with Session(self.engine) as session:
            try:
                session.add(new_srp)
                session.commit()
                return entropyId
            except IntegrityError:
                session.rollback()
                return False

    def get_short_lived_srp(self, username, accessionId):
        with Session(self.engine) as session:
            srp = session.query(shortLivedSrpStart).filter(
                (shortLivedSrpStart.username == username) &
                (shortLivedSrpStart.consumed == False) &
                (shortLivedSrpStart.entropyId == accessionId) &
                (shortLivedSrpStart.created_on >= datetime.now() - timedelta(seconds=5))
            ).first()
            if srp:
                srp.consumed = True  # Mark as consumed
                session.commit()
                return {
                    "empheralA": srp.empheralA,
                    "empheralB": srp.empheralB,
                    "verifier": srp.verifier
                }
            return None

    def delete_short_lived_srp(self, username):
        with Session(self.engine) as session:
            srp = session.query(shortLivedSrpStart).filter(
                shortLivedSrpStart.username == username
            ).first()
            if srp:
                session.delete(srp)
                session.commit()
                return True
            return False

    def delete_expired_short_lived_srps(self):
        with Session(self.engine) as session:
            now = datetime.now(timezone.utc)
            expired_srps = session.query(shortLivedSrpStart).filter(
                (shortLivedSrpStart.created_on < now - timedelta(seconds=5)) |
                (shortLivedSrpStart.consumed == True)
            ).all()
            for srp in expired_srps:
                session.delete(srp)
            session.commit()

    def delete_expired_sessions(self):
        with Session(self.engine) as session:
            now = datetime.now(timezone.utc)
            expired_sessions = session.query(PassAppSessions).filter(
                (PassAppSessions.expires_on < now)
            ).all()
            for es in expired_sessions:
                session.delete(es)
            session.commit()

    def increase_login_attempt(self, username):
        with Session(self.engine) as session:
            user = session.query(PassAppUsers).filter_by(username=username).first()
            if user:
                user.login_attempts += 1
                user.last_login_attempt = datetime.now()
                session.commit()
                return True
            return False

    def get_login_attempts(self, username):
        with Session(self.engine) as session:
            user = session.query(PassAppUsers).filter_by(username=username).first()
            if user:
                return user.login_attempts
            return 99

    def set_session(self, username, ip):
        with Session(self.engine) as session:
            user = session.query(PassAppUsers).filter_by(username=username).first()
            if not user:
                return None

            now = datetime.now(timezone.utc)
            user.last_login_attempt = now
            user.login_attempts = 0

            # Create session UUID
            new_session = PassAppSessions(
                user=user,
                expires_on=datetime.now(timezone.utc) + timedelta(hours=24),
                ip_address=ip
            )
            session.add(new_session)
            session.commit()
            return new_session.session_uuid

    def validate_session(self, token, ip=None, extend_minutes=30):
        with Session(self.engine) as s:
            sess = s.query(PassAppSessions).filter_by(session_uuid=token,ip_address=ip).first()
            if not sess: return None
            if int(sess.expires_on.timestamp()) <= int(datetime.now(timezone.utc).timestamp()):
                s.delete(sess); s.commit()
                return None
            sess.last_accessed = datetime.now(timezone.utc)
            sess.expires_on = datetime.now(timezone.utc) + timedelta(minutes=extend_minutes)
            s.commit()
            return s.query(PassAppUsers).get(sess.user_id)

    def destroy_session(self, token):
        with Session(self.engine) as s:
            sess = s.query(PassAppSessions).filter_by(session_uuid=token).first()
            if not sess: return None
            s.delete(sess); s.commit()
            return None

    def listUserVaults(self, userId):
        with Session(self.engine) as session:
            keePassVaults = session.query(KeePassVaults).filter(
                KeePassVaults.user_id == userId,
            ).all()
            vaultNames = [vault.vault_name for vault in keePassVaults]
            return vaultNames

    def getUserVault(self, userId, vaultName):
        with Session(self.engine) as session:
            keePassVault = session.query(KeePassVaults).filter(
                KeePassVaults.user_id == userId,
                KeePassVaults.vault_name == vaultName,
            ).first()
            return keePassVault.vault_data

    def addUserVault(self, userId, vaultName, vaultData):
        import hashlib
        vault_hash = hashlib.sha256(vaultData).hexdigest()

        new_vault = KeePassVaults(
            user_id=userId,
            vault_name=vaultName,
            vault_data=vaultData,
            sha256=vault_hash,
            version=1
        )
        with Session(self.engine) as session:
            try:
                session.add(new_vault)
                session.commit()
                return True
            except IntegrityError:
                session.rollback()
                return False