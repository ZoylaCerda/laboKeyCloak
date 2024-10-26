from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import logging

# Configuración del logger para identificar errores de conexión fácilmente
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# URL de conexión a la base de datos (asegúrate de que sea correcta)
DATABASE_URL = (
    "postgresql://default:1jVHilOm4rEw@ep-green-hat-a4mtqx6b.us-east-1.aws.neon.tech:5432/lab?sslmode=require"
)

# Creación del motor SQLAlchemy para conectar a la base de datos
try:
    engine = create_engine(DATABASE_URL, echo=True)  # echo=True para ver las consultas SQL en los logs
    with engine.connect() as connection:
        logger.info("Conexión exitosa a la base de datos.")
except Exception as e:
    logger.error(f"Ocurrió un error al conectar a la base de datos: {e}")
    raise

# Configuración de la sesión de SQLAlchemy
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base para los modelos (todas las clases de modelo heredarán de esta base)
Base = declarative_base()

# Dependencia para obtener una sesión de base de datos
def get_db():
    """Provee una sesión de base de datos para ser utilizada en los endpoints."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Creación de las tablas si no existen
def create_tables():
    """Crea las tablas en la base de datos."""
    try:
        logger.info("Creando tablas en la base de datos si no existen...")
        Base.metadata.create_all(bind=engine)
        logger.info("Tablas creadas o verificadas exitosamente.")
    except Exception as e:
        logger.error(f"Error al crear las tablas: {e}")
        raise

# Llamar a create_tables() para asegurar la creación de las tablas al iniciar
create_tables()
