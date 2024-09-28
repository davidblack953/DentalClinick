# models.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

# Inicialización de la base de datos
db = SQLAlchemy()

# Modelo de Usuario
class Usuario(UserMixin, db.Model):
    __tablename__ = 'usuarios'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    rol = db.Column(db.String(64), nullable=False)  # Ejemplo: 'administrador', 'odontologo', 'recepcionista'



# Modelo de Cita
class Cita(db.Model):
    __tablename__ = 'citas'
    id = db.Column(db.Integer, primary_key=True)
    fecha = db.Column(db.DateTime, nullable=False)
    motivo = db.Column(db.String(256), nullable=False)
    paciente_id = db.Column(db.Integer, db.ForeignKey('pacientes.id'), nullable=False)
    odontologo_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)


class Paciente(db.Model):
    __tablename__ = 'pacientes'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(64), nullable=False)
    apellido = db.Column(db.String(64), nullable=False)
    fecha_nacimiento = db.Column(db.Date, nullable=False)
    historial_medico = db.Column(db.Text)
    # Otras columnas relacionadas con el paciente (como dirección, teléfono, etc.)

    def __repr__(self):
        return f'<Paciente {self.nombre} {self.apellido}>'

# Si más adelante necesitas otros modelos (e.g. facturación, historial), también se pueden agregar aquí.
# Modelo de Paciente
"""class Paciente(db.Model):
    __tablename__ = 'pacientes'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(64), nullable=False)
    apellido = db.Column(db.String(64), nullable=False)
    fecha_nacimiento = db.Column(db.Date, nullable=False)
    historial_medico = db.Column(db.Text)"""