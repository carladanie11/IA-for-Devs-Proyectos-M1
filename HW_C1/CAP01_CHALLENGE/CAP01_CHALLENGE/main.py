from fastapi import FastAPI, HTTPException, Depends
from typing import List
from pydantic import BaseModel
from passlib.context import CryptContext
import jwt

# Base de datos simulada
fake_db = {"users": {}}

# Configuración de FastAPI
app = FastAPI()

# Configuración de Passlib para el cifrado de contraseñas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Clave secreta para JWT
SECRET_KEY = "mysecretkey"

# Modelos de datos
class Payload(BaseModel):
    numbers: List[int]

class BinarySearchPayload(BaseModel):
    numbers: List[int]
    target: int

class User(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str

# Funciones auxiliares
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_token(username: str) -> str:
    return jwt.encode({"username": username}, SECRET_KEY, algorithm="HS256")

def decode_token(token: str) -> str:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload["username"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")

def verify_token(token: str = Depends(decode_token)):
    return token

# Endpoints
@app.get("/")
def read_root():
    return {"message": "¡Bienvenido a mi API!"}

@app.post("/register")
def register(user: User):
    if user.username in fake_db["users"]:
        raise HTTPException(status_code=400, detail="El usuario ya existe")
    hashed_password = hash_password(user.password)
    fake_db["users"][user.username] = hashed_password
    return {"message": "Usuario registrado exitosamente"}

@app.post("/login")
def login(user: User):
    if user.username not in fake_db["users"]:
        raise HTTPException(status_code=400, detail="Usuario no encontrado")
    hashed_password = fake_db["users"][user.username]
    if not verify_password(user.password, hashed_password):
        raise HTTPException(status_code=400, detail="Contraseña incorrecta")
    token = create_token(user.username)
    return {"access_token": token}

@app.post("/bubble-sort")
def bubble_sort(payload: Payload, token: str = Depends(verify_token)):
    numbers = payload.numbers
    n = len(numbers)
    for i in range(n):
        for j in range(0, n - i - 1):
            if numbers[j] > numbers[j + 1]:
                numbers[j], numbers[j + 1] = numbers[j + 1], numbers[j]
    return {"numbers": numbers}

@app.post("/filter-even")
def filter_even(payload: Payload, token: str = Depends(verify_token)):
    even_numbers = [num for num in payload.numbers if num % 2 == 0]
    return {"even_numbers": even_numbers}

@app.post("/sum-elements")
def sum_elements(payload: Payload, token: str = Depends(verify_token)):
    total = sum(payload.numbers)
    return {"sum": total}

@app.post("/max-value")
def max_value(payload: Payload, token: str = Depends(verify_token)):
    if not payload.numbers:
        raise HTTPException(status_code=400, detail="La lista no puede estar vacía")
    return {"max": max(payload.numbers)}

@app.post("/binary-search")
def binary_search(payload: BinarySearchPayload, token: str = Depends(verify_token)):
    numbers = payload.numbers
    target = payload.target
    left, right = 0, len(numbers) - 1
    while left <= right:
        mid = (left + right) // 2
        if numbers[mid] == target:
            return {"found": True, "index": mid}
        elif numbers[mid] < target:
            left = mid + 1
        else:
            right = mid - 1
    return {"found": False, "index": -1}
