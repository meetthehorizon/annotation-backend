from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models import db, User, Assignment, USR

reviewer_bp = Blueprint('reviewer', __name__)


@reviewer_bp.route('/assignments', methods=['GET'])
@jwt_required()
def get_reviewer_assignments():
    email = get_jwt_identity()
    user = User.query.filter_by(email=email).first()

    if not user or user.role != 'reviewer':
        return jsonify({"msg": "Reviewer access only"}), 403

    assignments = Assignment.query.filter_by(reviewer_id=user.id).all()
    result = []

    for a in assignments:
        usr = USR.query.get(a.usr_id)
        result.append({
            "assignment_id": a.id,
            "usr_id": usr.id,
            "segment_id": usr.segment_id,
            "status": usr.status,
            "data": usr.data,
            "annotation_status": a.annotation_status
        })

    return jsonify(result)


@reviewer_bp.route('/usr/<int:usr_id>', methods=['GET'])
@jwt_required()
def get_usr_for_review(usr_id):
    email = get_jwt_identity()
    user = User.query.filter_by(email=email).first()

    assignment = Assignment.query.filter_by(usr_id=usr_id, reviewer_id=user.id).first()
    if not assignment:
        return jsonify({"msg": "Not assigned to this USR"}), 403

    usr = USR.query.get(usr_id)
    return jsonify({
        "usr_id": usr.id,
        "segment_id": usr.segment_id,
        "status": usr.status,
        "data": usr.data
    })


@reviewer_bp.route('/usr/<int:usr_id>', methods=['PUT'])
@jwt_required()
def review_usr(usr_id):
    email = get_jwt_identity()
    user = User.query.filter_by(email=email).first()

    assignment = Assignment.query.filter_by(usr_id=usr_id, reviewer_id=user.id).first()
    if not assignment:
        return jsonify({"msg": "Not assigned to this USR"}), 403

    data = request.json
    status = data.get("status")  # 'Reviewed' or 'Needs Revision'

    if status not in ['Reviewed', 'Needs Revision']:
        return jsonify({"msg": "Invalid review status"}), 400

    usr = USR.query.get(usr_id)
    usr.status = status
    assignment.annotation_status = status

    db.session.commit()
    return jsonify({"msg": f"USR marked as {status}"})
