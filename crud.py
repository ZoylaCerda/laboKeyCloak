from sqlalchemy.orm import Session
from models import Shoe
from schemas import ShoeCreate
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Crear un zapato
def create_shoe(db: Session, shoe: ShoeCreate):
    try:
        db_shoe = Shoe(**shoe.dict())
        db.add(db_shoe)
        db.commit()
        db.refresh(db_shoe)
        logger.info(f"Shoe created: {db_shoe}")
        return db_shoe
    except Exception as e:
        logger.error(f"Error creating shoe: {e}")
        db.rollback()
        raise

# Obtener un zapato por ID
def get_shoe(db: Session, shoe_id: int):
    return db.query(Shoe).filter(Shoe.id == shoe_id).first()

# Obtener todos los zapatos con paginación
def get_shoes(db: Session, skip: int = 0, limit: int = 10):
    return db.query(Shoe).offset(skip).limit(limit).all()

# Actualizar stock de un zapato
def update_shoe_stock(db: Session, shoe_id: int):
    shoe = db.query(Shoe).filter(Shoe.id == shoe_id).first()
    if shoe:
        db.commit()
        db.refresh(shoe)
        return shoe
    return None

# Eliminar un zapato por ID
def delete_shoe(db: Session, shoe_id: int):
    shoe = db.query(Shoe).filter(Shoe.id == shoe_id).first()
    if shoe:
        db.delete(shoe)
        db.commit()
        return True
    return False
