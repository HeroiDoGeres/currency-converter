from fastapi import Depends, FastAPI, HTTPException, status, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse
import requests_async as reqs
from jose import JWTError, jwt
from passlib.context import CryptContext
from typing import Union
from pydantic import BaseModel
from datetime import datetime, timedelta


FIXER_API_URL = 'http://api.apilayer.com/fixer/'
FIXER_ACCESS_KEY = 'x3EZJdGAJOegQDVJa9NN2pVFXZYC6hsX'
FAKE_USERS_DB = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    },
}

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


async def fixer_req(endpoint: str, query_params: dict = None):
    """
    Utility function that abstracts away boilerplate code like adding api key to
    the request headers or concatenating query parameters.
    :arg str endpoint: api endpoint
    :arg dict query_params: query parameters
    """
    if not query_params:
        return await reqs.get(f'{FIXER_API_URL}{endpoint}', headers={"apikey": FIXER_ACCESS_KEY})
    query = f"{FIXER_API_URL}{endpoint}?{'&'.join([f'{key}={value}' for key, value in query_params.items()])}"
    return await reqs.get(query, headers={"apikey": FIXER_ACCESS_KEY})


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Union[str, None] = None


class User(BaseModel):
    username: str
    email: Union[str, None] = None
    full_name: Union[str, None] = None
    disabled: Union[bool, None] = None


class UserInDB(User):
    hashed_password: str


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(FAKE_USERS_DB, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


app = FastAPI()


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """Authentication endpoint."""
    user = authenticate_user(FAKE_USERS_DB, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/", response_class=HTMLResponse)
def root():
    """
    Root endpoint, who says the user can't be welcomed and guided even in a dummie project?
    """
    return """
    <html>
        <head>
            <title>Currency Converter API</title>
        </head>
        <body>
            <h4>Hello there!</h4>
            Please go into the <a href="/docs">automatic interactive API documentation</a>, there you can authenticate
            using the username 'johndoe' and password 'secret'.<br/>
            Worry not, we're giving the password away in plain text because this is for demonstration purposes only.<br/><br/>
            Afterwards you're good to go and use the API, there might be some limitations regarding the number of requests
            you can make daily since we're using a free api on the backend (Fixer to be specific).<br/>
            You also have access to historical data all the way back to 1999.
        </body>
    </html>
    """


@app.get("/currencies")
async def currencies(current_user: User = Depends(get_current_active_user)):
    """Lists all supported currencies."""
    res = await fixer_req('symbols')
    return res.json().get('symbols')


@app.get("/convert")
async def convert(base: str, target: str, amount: float, date: Union[str, None] = Query(None, description="Should be formatted as YYYY-MM-DD.",),
    current_user: User = Depends(get_current_active_user)):
    """
    Converts a given amount from one currency to another according to rates of the current day.
    Can also receive a date and use historical rates data to make the conversion.
    :arg str base: symbol of the base currency
    :arg str target: symbol of the target currency
    :arg float amount: amount of base currency that should be converted into target currency.
    :arg date:
        date from which rates should be used for the convertion, should be formatted
        as 'YYYY-MM-DD' and defaults to the current day
    :type date: str, optional
    :return: amount converted into target currency
    """
    req_params = {'from': base, 'to': target, 'amount': amount}
    if date:
        req_params['date'] = date
    res = await fixer_req('convert', req_params)
    return res.json().get('result')
