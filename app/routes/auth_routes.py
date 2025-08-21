from flask import Blueprint, request, jsonify
from app.extensions import db
from app.models import User
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity

auth_bp = Blueprint('auth', __name__)

# Register (Admin only)
@auth_bp.route('/register', methods=['POST'])
@jwt_required()
def register():
    current_user_email = get_jwt_identity()
    current_user = User.query.filter_by(email=current_user_email).first()
    if not current_user or current_user.role != 'admin':
        return jsonify({"msg": "Admin privileges required"}), 403

    data = request.json
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role')

    if User.query.filter_by(email=email).first():
        return jsonify({"msg": "User already exists"}), 400

    user = User(name=name, email=email, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify({"msg": "User created"}), 201


# Login
@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({"msg": "Bad email or password"}), 401

    # Include additional claims (like role) in the token
    access_token = create_access_token(
        identity=user.email,
        additional_claims={"role": user.role}
    )
    return jsonify(access_token=access_token)

# Profile (protected)
@auth_bp.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    current_user_email = get_jwt_identity()
    user = User.query.filter_by(email=current_user_email).first()
    if not user:
        return jsonify({"msg": "User not found"}), 404

    return jsonify({
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "role": user.role
    })
