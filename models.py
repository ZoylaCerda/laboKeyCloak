from sqlalchemy import Column, Integer, String, Boolean
from database import Base

class Shoe(Base):
    __tablename__ = "shoes"

    id = Column(Integer, primary_key=True, index=True)
    brand = Column(String, index=True, nullable=False)  # Marca del zapato (obligatorio)
    size = Column(Integer, index=True, nullable=False)  # Tamaño del zapato (obligatorio)
