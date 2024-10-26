from pydantic import BaseModel
from typing import List

class ShoeBase(BaseModel):
    brand: str
    size: float
    

class ShoeCreate(BaseModel):
    brand: str
    size: int

    class Config:
        orm_mode = True  


class Shoe(ShoeBase):
    id: int

    class Config:
        orm_mode = True
        
        
class Register(BaseModel):
    email: str
    password: str
    
class UserSignInRequest(BaseModel):
    email: str
    password: str
    