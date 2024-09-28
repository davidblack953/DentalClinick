from flask_wtf import FlaskForm
from wtforms import DateTimeField, StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, Optional, EqualTo


class RegistrationForm(FlaskForm):
    nombre = StringField('Nombre', validators=[DataRequired()])
    email = StringField('Correo electrónico', validators=[DataRequired(), Email()])
    password = PasswordField('Contraseña', validators=[DataRequired(), EqualTo('confirm', message='Las contraseñas deben coincidir')])
    confirm = PasswordField('Repetir Contraseña')
    rol = SelectField('Rol', choices=[('administrador', 'Administrador'), ('odontologo', 'Odontólogo'), ('recepcionista', 'Recepcionista')], validators=[DataRequired()])
    submit = SubmitField('Registrarse')


class UsuarioForm(FlaskForm):
    nombre = StringField('Nombre', validators=[DataRequired()])
    email = StringField('Correo electrónico', validators=[DataRequired(), Email()])
    password = PasswordField('Nueva Contraseña', validators=[Optional(), EqualTo('confirm', message='Las contraseñas deben coincidir')])
    confirm = PasswordField('Confirmar Contraseña')
    rol = SelectField('Rol', choices=[('administrador', 'Administrador'), ('odontologo', 'Odontólogo'), ('recepcionista', 'Recepcionista')], validators=[DataRequired()])
    submit = SubmitField('Guardar Usuario')
    
    
    
class CitaForm(FlaskForm):
    paciente_id = SelectField('Paciente', coerce=int, validators=[DataRequired()])
    odontologo_id = SelectField('Odontólogo', coerce=int, validators=[DataRequired()])
    fecha = DateTimeField('Fecha y Hora', format='%Y-%m-%d %H:%M', validators=[DataRequired()])
    motivo = StringField('Motivo de la Cita', validators=[DataRequired()])
    submit = SubmitField('Agendar Cita') 
    
       