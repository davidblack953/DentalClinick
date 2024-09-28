import datetime
from flask import Flask, jsonify, render_template, redirect, request, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user, login_user, login_required, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from forms import CitaForm, RegistrationForm,UsuarioForm
from models import Cita, Paciente, db, Usuario  # Importamos db y el modelo Usuario desde models.py
from werkzeug.security import generate_password_hash, check_password_hash
# Inicialización de la aplicación Flask
app = Flask(__name__)

# Configuración básica
app.config['SECRET_KEY'] = 'clave_secreta_segura'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dentalclinicbd.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicializamos la base de datos
db.init_app(app)

# Configuración de Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))

# Formularios
class LoginForm(FlaskForm):
    email = StringField('Correo electrónico', validators=[DataRequired(), Email()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    submit = SubmitField('Iniciar sesión')

"""class RegistrationForm(FlaskForm):
    nombre = StringField('Nombre', validators=[DataRequired()])
    email = StringField('Correo electrónico', validators=[DataRequired(), Email()])
    password = PasswordField('Contraseña', validators=[DataRequired(), EqualTo('confirm', message='Las contraseñas deben coincidir')])
    confirm = PasswordField('Repetir Contraseña')
    submit = SubmitField('Registrarse')"""

# Rutas
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Usuario.query.filter_by(email=form.email.data).first()
        if user:
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash('Has iniciado sesión con éxito.', 'success')
                return redirect(url_for('index'))
            else:
                flash('Contraseña incorrecta. Inténtalo de nuevo.', 'danger')
        else:
            flash('No se encontró una cuenta con ese correo electrónico.', 'warning')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/odontograma')
@login_required
def odontograma():
    return render_template('odontograma.html', title="Odontograma Dental")



@app.route('/historial')
@login_required
def historial():
    return render_template('historial.html', title="Historia Clínica Digital")

@app.route('/facturacion')
@login_required
def facturacion():
    return render_template('facturacion.html', title="Facturación Electrónica")


@app.route('/db_status')
def db_status():
    from sqlalchemy import inspect
    inspector = inspect(db.engine)
    tables = inspector.get_table_names()
    return f"Tablas en la base de datos: {tables}"




@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()  # Asegúrate de estar usando el formulario correcto
    print(form)  # Añade esta línea para depuración
    print(form._fields.keys())  # Añade esta línea para ver todos los campos
    if form.validate_on_submit():
        try:
            # Crear un nuevo usuario y almacenar la contraseña en forma de hash
            hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
            nuevo_usuario = Usuario(
                nombre=form.nombre.data,
                email=form.email.data,
                password_hash=hashed_password,
                rol=form.rol.data  # Obtiene el rol desde el formulario
            )
            db.session.add(nuevo_usuario)
            db.session.commit()  # Asegúrate de hacer commit para cerrar la transacción
            flash('Usuario registrado con éxito.')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()  # Rollback en caso de error para liberar la base de datos
            flash(f"Error en la base de datos: {str(e)}", 'danger')
    return render_template('register.html', form=form)


@app.route('/usuarios')
@login_required
def listar_usuarios():
    # Mostrar todos los usuarios (solo visible para administradores)
    if current_user.rol != 'administrador':
        flash('No tienes permisos para acceder a esta página.')
        return redirect(url_for('index'))
    
    usuarios = Usuario.query.all()
    return render_template('listar_usuarios.html', usuarios=usuarios)

@app.route('/usuario/nuevo', methods=['GET', 'POST'])
@login_required
def nuevo_usuario():
    # Solo administradores pueden crear usuarios
    if current_user.rol != 'administrador':
        flash('No tienes permisos para acceder a esta página.')
        return redirect(url_for('index'))
    
    form = UsuarioForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        nuevo_usuario = Usuario(
            nombre=form.nombre.data,
            email=form.email.data,
            password_hash=hashed_password,
            rol=form.rol.data
        )
        db.session.add(nuevo_usuario)
        db.session.commit()
        flash('Usuario creado con éxito.')
        return redirect(url_for('listar_usuarios'))
    return render_template('nuevo_usuario.html', form=form)

@app.route('/usuario/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_usuario(id):
    # Solo administradores pueden editar usuarios
    if current_user.rol != 'administrador':
        flash('No tienes permisos para acceder a esta página.')
        return redirect(url_for('index'))

    usuario = Usuario.query.get_or_404(id)
    form = UsuarioForm(obj=usuario)

    if form.validate_on_submit():
        usuario.nombre = form.nombre.data
        usuario.email = form.email.data
        if form.password.data:
            usuario.password_hash = generate_password_hash(form.password.data, method='sha256')
        usuario.rol = form.rol.data
        db.session.commit()
        flash('Usuario actualizado con éxito.')
        return redirect(url_for('listar_usuarios'))
    return render_template('editar_usuario.html', form=form)

@app.route('/usuario/eliminar/<int:id>', methods=['POST'])
@login_required
def eliminar_usuario(id):
    # Solo administradores pueden eliminar usuarios
    if current_user.rol != 'administrador':
        flash('No tienes permisos para acceder a esta página.')
        return redirect(url_for('index'))
    
    usuario = Usuario.query.get_or_404(id)
    db.session.delete(usuario)
    db.session.commit()
    flash('Usuario eliminado con éxito.')
    return redirect(url_for('listar_usuarios'))

# Punto de entrada de la aplicación
import os

@app.route('/actualizar_contrasenas', methods=['GET'])
@login_required
def actualizar_contrasenas():
    if current_user.rol != 'administrador':
        flash('No tienes permisos para acceder a esta página.')
        return redirect(url_for('index'))
    
    # Actualizar las contraseñas no hasheadas
    usuarios = Usuario.query.all()
    for usuario in usuarios:
        if not usuario.password_hash.startswith('pbkdf2:sha256'):  # Verificar si no está hasheada
            usuario.password_hash = generate_password_hash(usuario.password_hash, method='sha256')
            db.session.commit()
    
    flash('Contraseñas actualizadas con éxito.')
    return redirect(url_for('index'))


@app.route('/citas', methods=['GET', 'POST'])
@login_required
def citas():
    form = CitaForm()

    # Cargar los pacientes y odontólogos en los campos de selección
    form.paciente_id.choices = [(p.id, f"{p.nombre} {p.apellido}") for p in Paciente.query.all()]
    form.odontologo_id.choices = [(u.id, u.nombre) for u in Usuario.query.filter_by(rol='odontologo').all()]

    # Manejo del formulario si se envía
    if form.validate_on_submit():
        nueva_cita = Cita(
            fecha=form.fecha.data,
            motivo=form.motivo.data,
            paciente_id=form.paciente_id.data,
            odontologo_id=form.odontologo_id.data
        )
        db.session.add(nueva_cita)
        db.session.commit()
        flash('Cita agendada con éxito.')
        return redirect(url_for('citas'))  # Redireccionar después de crear la cita

    # Obtener todas las citas para mostrarlas en la página
    citas = Cita.query.all()
    return render_template('citas.html', form=form, citas=citas)



@app.route('/cita/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_cita(id):
    cita = Cita.query.get_or_404(id)
    form = CitaForm(obj=cita)
    
    form.paciente_id.choices = [(p.id, f"{p.nombre} {p.apellido}") for p in Paciente.query.all()]
    form.odontologo_id.choices = [(u.id, u.nombre) for u in Usuario.query.filter_by(rol='odontologo').all()]

    if form.validate_on_submit():
        cita.fecha = form.fecha.data
        cita.motivo = form.motivo.data
        cita.paciente_id = form.paciente_id.data
        cita.odontologo_id = form.odontologo_id.data
        db.session.commit()
        flash('Cita actualizada con éxito.')
        return redirect(url_for('ver_citas'))
    
    return render_template('editar_cita.html', form=form)


@app.route('/cita/eliminar/<int:id>', methods=['POST'])
@login_required
def eliminar_cita(id):
    cita = Cita.query.get_or_404(id)
    db.session.delete(cita)
    db.session.commit()
    flash('Cita eliminada con éxito.')
    return redirect(url_for('ver_citas'))
    

@app.route('/get_citas')
@login_required
def get_citas():
    citas = Cita.query.all()
    eventos = []

    for cita in citas:
        evento = {
            'title': f'{cita.paciente.nombre} {cita.paciente.apellido}',
            'start': cita.fecha.isoformat(),  # Asegúrate de que la fecha esté en formato ISO 8601
            'end': cita.fecha.isoformat(),  # Si las citas son de duración fija, puedes usar la misma hora para start y end
            'extendedProps': {
                'odontologo': cita.odontologo.nombre,
                'motivo': cita.motivo
            }
        }
        eventos.append(evento)

    return jsonify(eventos)

@app.route('/agendar_cita', methods=['POST'])
@login_required
def agendar_cita():
    paciente_id = request.form['paciente']
    odontologo_id = request.form['odontologo']
    fecha_hora = request.form['fechaHora']
    motivo = request.form['motivo']

    nueva_cita = Cita(
        paciente_id=paciente_id,
        odontologo_id=odontologo_id,
        fecha=datetime.fromisoformat(fecha_hora),
        motivo=motivo
    )
    db.session.add(nueva_cita)
    db.session.commit()

    return jsonify({'success': True})

@app.route('/calendario_citas')
@login_required
def calendario():
    return render_template('calendarioCitas.html')  # Asegúrate de tener esta plantilla
if __name__ == '__main__':
    with app.app_context():
        basedir = os.path.abspath(os.path.dirname(__file__))
        db_path = os.path.join(basedir, 'dentalclinicbd.db')
        print(f"Creando la base de datos en: {db_path}")
        db.create_all()  # Esto creará las tablas si no existen
        print("Tablas creadas.")
    app.run(debug=True,port=5050)
