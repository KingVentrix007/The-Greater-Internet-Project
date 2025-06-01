from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import asyncio
from sqlalchemy.future import select
from passlib.context import CryptContext


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
DATABASE_URL = "sqlite+aiosqlite:///database/users.db"
def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)
engine = create_async_engine(DATABASE_URL, echo=True)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)


async def get_user_by_username(db: AsyncSession, username: str):
    result = await db.execute(select(User).where(User.username == username))
    return result.scalars().first()

async def create_user(db: AsyncSession, username: str, password: str):
    user = User(username=username, hashed_password=hash_password(password))
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user
async def authenticate_user(db: AsyncSession, username: str, password: str):
    user = await get_user_by_username(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
async def get_token_db():
    async with AsyncSessionLocal() as session:
        yield session
async def get_token_db_dependency():
    return AsyncSessionLocal()
async def add_user_interactive():
    async with AsyncSessionLocal() as db:
        username = input("Enter username: ")
        password = input("Enter password: ")
        user = await create_user(db, username, password)
        verified_user = await get_user_by_username(db, username)
        if verified_user:
            print(f"✅ Verified: User '{verified_user.username}' exists in the database.")
        else:
            print(f"❌ Verification failed: User '{username}' not found.")
        # print(f"User created w

if __name__ == "__main__":
    asyncio.run(init_db())

    asyncio.run(add_user_interactive())


