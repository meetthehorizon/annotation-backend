from flask import Blueprint, current_app, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_mail import Message
from app.extensions import mail
from itsdangerous import URLSafeTimedSerializer
from app.models import db, User, Project, Chapter, Sentence, Segment, USR, Assignment
from app.models import (
    LexicalInfo,
    DependencyInfo,
    DiscourseCorefInfo,
    ConstructionInfo,
    SentenceTypeInfo,
)
import random
import string
from datetime import datetime, timedelta

admin_bp = Blueprint("admin", __name__)


# Helper to check admin
def admin_only():
    current_user_email = get_jwt_identity()
    user = User.query.filter_by(email=current_user_email).first()
    if not user or user.role != "admin":
        return None
    return user


# Generate token
def generate_token(email):
    serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
    return serializer.dumps(email, salt=current_app.config["SECURITY_PASSWORD_SALT"])


# Verify token
def verify_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
    try:
        email = serializer.loads(
            token, salt=current_app.config["SECURITY_PASSWORD_SALT"], max_age=expiration
        )
        return email
    except Exception:
        return False


# Users


@admin_bp.route("/users", methods=["GET"])
@jwt_required()
def get_users():
    if not admin_only():
        return jsonify({"msg": "Admin privileges required"}), 403

    users = User.query.all()
    return jsonify(
        [
            {
                "id": u.id,
                "email": u.email,
                "name": u.name,  # Assuming you have a name field
                "role": u.role,
            }
            for u in users
        ]
    )


# USER MANAGEMENT ROUTES


# Public registration endpoint (no JWT required)
@admin_bp.route("/register", methods=["POST"])
def register_user():
    data = request.json
    required_fields = ["email", "name", "organization", "password"]
    if not all(field in data for field in required_fields):
        return jsonify({"msg": "Missing required fields"}), 400

    # Check if user already exists
    if User.query.filter_by(email=data["email"]).first():
        return jsonify({"msg": "User already exists"}), 400

    try:
        user = User(
            email=data["email"],
            name=data["name"],
            organization=data["organization"],  # Make sure this matches your model
            role="pending",
            status="pending",
        )
        user.set_password(data["password"])  # Use set_password to hash the password
        db.session.add(user)
        db.session.commit()
        return (
            jsonify(
                {"msg": "Registration request submitted. Waiting for admin approval."}
            ),
            201,
        )
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": "Error creating user", "error": str(e)}), 500


# Get pending users (admin only)
@admin_bp.route("/pending_users", methods=["GET"])
@jwt_required()
def get_pending_users():
    if not admin_only():
        return jsonify({"msg": "Admin privileges required"}), 403

    pending_users = User.query.filter_by(status="pending").all()
    return jsonify(
        [
            {
                "id": u.id,
                "email": u.email,
                "name": u.name,
                "organization": u.organization,
                "role": u.role,
                "status": u.status,
            }
            for u in pending_users
        ]
    )


# Approve user (admin only)
@admin_bp.route("/approve_user/<int:user_id>", methods=["PUT"])
@jwt_required()
def approve_user(user_id):
    if not admin_only():
        return jsonify({"msg": "Admin privileges required"}), 403

    data = request.json
    user = User.query.get(user_id)
    if not user:
        return jsonify({"msg": "User not found"}), 404

    if user.status != "pending":
        return jsonify({"msg": "User is not in pending status"}), 400

    try:
        user.status = "approved"
        user.role = data.get(
            "role", "annotator"
        )  # Default to annotator if not specified
        db.session.commit()
        return jsonify({"msg": "User approved successfully"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": "Error approving user", "error": str(e)}), 500


# Reject user (admin only)
@admin_bp.route("/reject_user/<int:user_id>", methods=["PUT"])
@jwt_required()
def reject_user(user_id):
    if not admin_only():
        return jsonify({"msg": "Admin privileges required"}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({"msg": "User not found"}), 404

    if user.status != "pending":
        return jsonify({"msg": "User is not in pending status"}), 400

    try:
        user.status = "rejected"
        db.session.commit()
        return jsonify({"msg": "User rejected successfully"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": "Error rejecting user", "error": str(e)}), 500


@admin_bp.route("/user/<int:user_id>", methods=["PUT"])
@jwt_required()
def update_user(user_id):
    if not admin_only():
        return jsonify({"msg": "Admin privileges required"}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({"msg": "User not found"}), 404

    data = request.json
    try:
        if "name" in data:
            user.name = data["name"]
        if "role" in data:
            user.role = data["role"]
        if "password" in data:
            user.password = data["password"]  # Should be hashed in production

        db.session.commit()
        return jsonify({"msg": "User updated"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": "Error updating user", "error": str(e)}), 500


@admin_bp.route("/user/<int:user_id>", methods=["DELETE"])
@jwt_required()
def delete_user(user_id):
    if not admin_only():
        return jsonify({"msg": "Admin privileges required"}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({"msg": "User not found"}), 404

    try:
        # First delete assignments for this user
        Assignment.query.filter(
            (Assignment.annotator_id == user_id) | (Assignment.reviewer_id == user_id)
        ).delete()

        db.session.delete(user)
        db.session.commit()
        return jsonify({"msg": "User deleted"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": "Error deleting user", "error": str(e)}), 500


@admin_bp.route("/forgot_password", methods=["POST"])
def forgot_password():
    email = request.json.get("email")
    if not email:
        return jsonify({"msg": "Email is required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        # Don't reveal whether user exists for security
        return jsonify({"msg": "If this email exists, you'll receive an OTP"}), 200

    # Generate a 6-digit OTP
    otp = "".join(random.choices(string.digits, k=6))
    otp_expiration = datetime.utcnow() + timedelta(
        minutes=10
    )  # OTP valid for 10 minutes

    # Store OTP in user record
    user.otp = otp
    user.otp_expiration = otp_expiration
    db.session.commit()

    try:
        msg = Message(
            "Password Reset OTP",
            sender=current_app.config["MAIL_USERNAME"],
            recipients=[user.email],
            body=f"Your OTP for password reset is: {otp}\n\nThis OTP is valid for 10 minutes.",
        )

        mail.connect()  # Check if connection works
        mail.send(msg)  # Send the email

        return jsonify({"msg": "OTP sent to your email"}), 200
    except Exception as e:
        current_app.logger.error(f"📧 Email Error: {str(e)}")
        return (
            jsonify(
                {
                    "msg": "Failed to send email",
                    "error": str(e),
                    "smtp_server": current_app.config["MAIL_SERVER"],
                    "smtp_port": current_app.config["MAIL_PORT"],
                }
            ),
            500,
        )


@admin_bp.route("/verify_otp", methods=["POST"])
def verify_otp():
    email = request.json.get("email")
    otp = request.json.get("otp")

    if not email or not otp:
        return jsonify({"msg": "Email and OTP are required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"msg": "Invalid request"}), 400

    if user.otp != otp:
        return jsonify({"msg": "Invalid OTP"}), 400

    if datetime.utcnow() > user.otp_expiration:
        return jsonify({"msg": "OTP has expired"}), 400

    # OTP is valid - generate a short-lived token for password reset
    token = generate_token(user.email)
    return jsonify({"msg": "OTP verified successfully", "reset_token": token}), 200


@admin_bp.route("/reset_password", methods=["POST"])
def reset_password():
    token = request.json.get("token")
    new_password = request.json.get("new_password")

    if not token or not new_password:
        return jsonify({"msg": "Token and new password are required"}), 400

    email = verify_token(token)
    if not email:
        return jsonify({"msg": "Invalid or expired token"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"msg": "User not found"}), 404

    try:
        user.set_password(new_password)
        # Clear the OTP after successful password reset
        user.otp = None
        user.otp_expiration = None
        db.session.commit()
        return jsonify({"msg": "Password updated successfully"}), 200
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error resetting password: {str(e)}")
        return jsonify({"msg": "Error resetting password"}), 500


# PROJECT ROUTES
@admin_bp.route("/project", methods=["POST"])
@jwt_required()
def create_project():
    if not admin_only():
        return jsonify({"msg": "Admin privileges required"}), 403

    data = request.json
    project = Project(
        title=data["title"],
        description=data.get("description"),
        language=data.get("language", "hindi"),  # Add this line
    )
    db.session.add(project)
    db.session.commit()
    return jsonify({"msg": "Project created", "project_id": project.id})


@admin_bp.route("/projects", methods=["GET"])
@jwt_required()
def get_projects():
    try:
        admin = admin_only()
        if not admin:
            return (
                jsonify({"msg": "Admin privileges required", "error": "unauthorized"}),
                403,
            )

        projects = Project.query.all()
        if not projects:
            return jsonify([])  # Return empty array if no projects

        project_list = [
            {
                "id": p.id,
                "title": p.title,
                "description": p.description,
                "chapter_count": len(p.chapters),
            }
            for p in projects
        ]

        return jsonify(project_list)

    except Exception as e:
        # Log the error for debugging
        current_app.logger.error(f"Error fetching projects: {str(e)}")
        return jsonify({"msg": "Server error", "error": str(e)}), 500


@admin_bp.route("/project/<int:project_id>", methods=["DELETE"])
@jwt_required()
def delete_project(project_id):
    if not admin_only():
        return jsonify({"msg": "Admin privileges required"}), 403

    project = Project.query.get(project_id)
    if not project:
        return jsonify({"msg": "Project not found"}), 404

    try:
        # Due to cascade='all, delete-orphan' in relationships, all related
        # chapters, sentences, segments, USRs and assignments will be deleted
        db.session.delete(project)
        db.session.commit()
        return jsonify({"msg": "Project and all its contents deleted successfully"})
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error deleting project: {str(e)}")
        return jsonify({"msg": "Error deleting project", "error": str(e)}), 500


@admin_bp.route("/project/<int:project_id>", methods=["GET"])
@jwt_required()
def get_project(project_id):
    if not admin_only():
        return jsonify({"msg": "Admin privileges required"}), 403

    project = Project.query.get(project_id)
    if not project:
        return jsonify({"msg": "Project not found"}), 404

    return jsonify(
        {
            "id": project.id,
            "title": project.title,
            "description": project.description,
            "chapter_count": len(project.chapters),
        }
    )


# CHAPTER ROUTES
@admin_bp.route("/project/<int:project_id>/chapter", methods=["POST"])
@jwt_required()
def create_chapter(project_id):
    if not admin_only():
        return jsonify({"msg": "Admin privileges required"}), 403

    data = request.json
    if not data or "name" not in data:
        return jsonify({"msg": "Chapter name is required"}), 400

    project = Project.query.get(project_id)
    if not project:
        return jsonify({"msg": "Project not found"}), 404

    chapter = Chapter(
        project_id=project_id,
        title=data["name"],
        language=project.language,  # Propagate language from project
    )
    db.session.add(chapter)
    db.session.commit()
    return jsonify(
        {"msg": "Chapter created", "chapter_id": chapter.id, "title": chapter.title}
    )


@admin_bp.route("/project/<int:project_id>/chapters", methods=["GET"])
@jwt_required()
def get_project_chapters(project_id):
    if not admin_only():
        return jsonify({"msg": "Admin privileges required"}), 403

    project = Project.query.get(project_id)
    if not project:
        return jsonify({"msg": "Project not found"}), 404

    chapters = Chapter.query.filter_by(project_id=project_id).all()
    return jsonify(
        [
            {
                "id": chapter.id,
                "title": chapter.title,
                "project_id": chapter.project_id,
                "sentence_count": len(chapter.sentences),
            }
            for chapter in chapters
        ]
    )


@admin_bp.route("/chapter/<int:chapter_id>", methods=["GET"])
@jwt_required()
def get_chapter(chapter_id):
    if not admin_only():
        return jsonify({"msg": "Admin privileges required"}), 403

    chapter = Chapter.query.get(chapter_id)
    if not chapter:
        return jsonify({"msg": "Chapter not found"}), 404

    return jsonify(
        {
            "id": chapter.id,
            "title": chapter.title,
            "project_id": chapter.project_id,
            "sentence_count": len(chapter.sentences),
        }
    )


@admin_bp.route("/chapter/<int:chapter_id>/segments", methods=["GET"])
@jwt_required()
def get_chapter_segments(chapter_id):
    if not admin_only():
        return jsonify({"msg": "Admin privileges required"}), 403

    chapter = Chapter.query.get(chapter_id)
    if not chapter:
        return jsonify({"msg": "Chapter not found"}), 404

    segments = []
    for sentence in chapter.sentences:
        segments.extend(sentence.segments)

    return jsonify(
        [
            {
                "id": segment.id,
                "segment_id": segment.segment_id,
                "text": segment.text,
                "sentence_id": segment.sentence_id,
            }
            for segment in segments
        ]
    )


@admin_bp.route("/chapter/<int:chapter_id>", methods=["DELETE"])
@jwt_required()
def delete_chapter(chapter_id):
    if not admin_only():
        return jsonify({"msg": "Admin privileges required"}), 403

    chapter = Chapter.query.get(chapter_id)
    if not chapter:
        return jsonify({"msg": "Chapter not found"}), 404

    try:
        # Will cascade to sentences, segments, USRs and assignments
        db.session.delete(chapter)
        db.session.commit()
        return jsonify({"msg": "Chapter and all its contents deleted successfully"})
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error deleting chapter: {str(e)}")
        return jsonify({"msg": "Error deleting chapter", "error": str(e)}), 500


# SENTENCE ROUTES
@admin_bp.route("/chapter/<int:chapter_id>/sentence", methods=["POST"])
@jwt_required()
def create_sentence(chapter_id):
    if not admin_only():
        return jsonify({"msg": "Admin privileges required"}), 403

    data = request.json
    if not data or "sentences" not in data:
        return jsonify({"msg": "Sentences data required"}), 400

    created = []
    for sent_data in data["sentences"]:
        sentence = Sentence(
            chapter_id=chapter_id,
            text=sent_data.get("text"),
            sentence_id=sent_data.get("sentence_id"),  # e.g., Geo_nios_3ch_0002
        )
        db.session.add(sentence)
        db.session.flush()
        created.append(
            {
                "sentence_id": sentence.id,
                "text": sentence.text,
                "chapter_id": sentence.chapter_id,
            }
        )

    db.session.commit()
    return jsonify({"msg": "Sentences added", "sentences": created})


@admin_bp.route("/chapter/<int:chapter_id>/sentences", methods=["GET"])
@jwt_required()
def get_chapter_sentences(chapter_id):
    if not admin_only():
        return jsonify({"msg": "Admin privileges required"}), 403

    chapter = Chapter.query.get(chapter_id)
    if not chapter:
        return jsonify({"msg": "Chapter not found"}), 404

    sentences = Sentence.query.filter_by(chapter_id=chapter_id).all()
    return jsonify(
        [
            {
                "id": sentence.id,
                "text": sentence.text,
                "sentence_id": sentence.sentence_id,
                "chapter_id": sentence.chapter_id,
                "segment_count": len(sentence.segments),
            }
            for sentence in sentences
        ]
    )


@admin_bp.route("/sentence/<int:sentence_id>", methods=["DELETE"])
@jwt_required()
def delete_sentence(sentence_id):
    if not admin_only():
        return jsonify({"msg": "Admin privileges required"}), 403

    sentence = Sentence.query.get(sentence_id)
    if not sentence:
        return jsonify({"msg": "Sentence not found"}), 404

    try:
        # Will cascade to segments, USRs and assignments
        db.session.delete(sentence)
        db.session.commit()
        return jsonify({"msg": "Sentence and all its contents deleted successfully"})
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error deleting sentence: {str(e)}")
        return jsonify({"msg": "Error deleting sentence", "error": str(e)}), 500


# SEGMENT ROUTES
@admin_bp.route("/sentence/<int:sentence_id>/segment", methods=["POST"])
@jwt_required()
def create_segment(sentence_id):
    if not admin_only():
        return jsonify({"msg": "Admin privileges required"}), 403

    # Handle both raw text and JSON input
    if request.content_type == "text/plain":
        raw_text = request.data.decode("utf-8")
        segments = []
        for line in raw_text.split("\n"):
            line = line.strip()
            if not line:
                continue

            # Split by tab and ensure we have exactly 4 parts
            parts = [part.strip() for part in line.split("\t")]
            if len(parts) != 4:
                continue  # or return error if you prefer

            segments.append(
                {
                    "segment_id": parts[0],
                    "text": parts[1],
                    "wxtext": parts[2],
                    "englishtext": parts[3],
                }
            )
    else:
        data = request.get_json()
        if not data or "segments" not in data:
            return jsonify({"msg": "Segments data required"}), 400
        segments = data["segments"]

    # Validate and create segments
    created = []
    for seg_data in segments:
        # Check for required fields
        required_fields = ["segment_id", "text", "wxtext", "englishtext"]
        if not all(field in seg_data for field in required_fields):
            return (
                jsonify(
                    {
                        "msg": "Each segment must have segment_id, text, wxtext, and englishtext fields",
                        "error": "missing_fields",
                        "received_data": seg_data,  # This will help debug what was actually received
                    }
                ),
                400,
            )

        segment = Segment(
            sentence_id=sentence_id,
            segment_id=seg_data["segment_id"],
            text=seg_data["text"],
            wxtext=seg_data["wxtext"],
            englishtext=seg_data["englishtext"],
        )

        db.session.add(segment)
        db.session.flush()

        created.append(
            {
                "id": segment.id,
                "segment_id": segment.segment_id,
                "text": segment.text,
                "wxtext": segment.wxtext,
                "englishtext": segment.englishtext,
            }
        )

    db.session.commit()
    return jsonify(
        {"msg": f"{len(created)} segments added successfully", "segments": created}
    )


@admin_bp.route("/sentence/<int:sentence_id>/segments", methods=["GET"])
@jwt_required()
def get_sentence_segments(sentence_id):
    if not admin_only():
        return jsonify({"msg": "Admin privileges required"}), 403

    sentence = Sentence.query.get(sentence_id)
    if not sentence:
        return jsonify({"msg": "Sentence not found"}), 404

    segments = Segment.query.filter_by(sentence_id=sentence_id).all()
    return jsonify(
        [
            {
                "id": segment.id,
                "text": segment.text,
                "wxtext": segment.wxtext,
                "englishtext": segment.englishtext,
                "segment_id": segment.segment_id,
                "sentence_id": segment.sentence_id,
                "usr_count": len(segment.usrs),
            }
            for segment in segments
        ]
    )


@admin_bp.route("/segment/<int:segment_id>", methods=["DELETE"])
@jwt_required()
def delete_segment(segment_id):
    if not admin_only():
        return jsonify({"msg": "Admin privileges required"}), 403

    segment = Segment.query.get(segment_id)
    if not segment:
        return jsonify({"msg": "Segment not found"}), 404

    try:
        # Will cascade to USRs and assignments
        db.session.delete(segment)
        db.session.commit()
        return jsonify({"msg": "Segment and all its USRs deleted successfully"})
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error deleting segment: {str(e)}")
        return jsonify({"msg": "Error deleting segment", "error": str(e)}), 500


@admin_bp.route("/segment/<int:segment_id>/usrs", methods=["GET"])
@jwt_required()
def get_segment_usrs(segment_id):
    if not admin_only():
        return jsonify({"msg": "Admin privileges required"}), 403

    segment = Segment.query.get(segment_id)
    if not segment:
        return jsonify({"msg": "Segment not found"}), 404

    usrs = USR.query.filter_by(segment_id=segment_id).all()
    return jsonify(
        [
            {
                "id": usr.id,
                "sentence_type": usr.sentence_type,
                "status": usr.status,
                "lexical_info": [
                    {
                        "concept": li.concept,
                        "index": li.index,
                        "semantic_category": li.semantic_category,
                        "morpho_semantic": li.morpho_semantic,
                        "speakers_view": li.speakers_view,
                    }
                    for li in usr.lexical_info
                ],
                "dependency_info": [
                    {
                        "concept": di.concept,
                        "index": di.index,
                        "head_index": di.head_index,
                        "relation": di.relation,
                    }
                    for di in usr.dependency_info
                ],
                "discourse_coref_info": [
                    {
                        "concept": dci.concept,
                        "index": dci.index,
                        "head_index": dci.head_index,
                        "relation": dci.relation,
                    }
                    for dci in usr.discourse_coref_info
                ],
                "construction_info": [
                    {
                        "concept": ci.concept,
                        "index": ci.index,
                        "cxn_index": ci.cxn_index,
                        "component_type": ci.component_type,
                    }
                    for ci in usr.construction_info
                ],
                "sentence_type_info": {
                    "sentence_type": usr.sentence_type,
                    "scope": (
                        usr.sentence_type_info[0].scope
                        if usr.sentence_type_info
                        else "neutral"
                    ),
                },
            }
            for usr in usrs
        ]
    )


@admin_bp.route("/visualize_usr/<int:segment_id>", methods=["GET"])
@jwt_required()
def visualize_usr(segment_id):
    if not admin_only():
        return jsonify({"msg": "Admin privileges required"}), 403

    segment = Segment.query.get(segment_id)
    if not segment:
        return jsonify({"msg": "Segment not found"}), 404

    usrs = USR.query.filter_by(segment_id=segment_id).all()
    if not usrs:
        return jsonify({"msg": "No USRs found for this segment"}), 404

    # We'll visualize the first USR (assuming one USR per segment)
    usr = usrs[0]

    # Generate the USR text in the standard format
    usr_lines = []

    # Add segment_id header
    usr_lines.append(f"<segment_id={segment.segment_id}>")

    # Add sentence text (commented)
    usr_lines.append(f"#{segment.text}")

    # Add lexical info lines
    for li in sorted(usr.lexical_info, key=lambda x: x.index):
        line_parts = [
            li.concept,
            str(li.index),
            li.semantic_category if li.semantic_category else "-",
            li.morpho_semantic if li.morpho_semantic else "-",
            # Dependency info
            " ".join(
                [
                    f"{di.head_index}:{di.relation}"
                    for di in sorted(usr.dependency_info, key=lambda x: x.index)
                    if di.index == li.index
                ]
            )
            or "-",
            # Discourse/Coref info
            " ".join(
                [
                    f"{dci.head_index}:{dci.relation}"
                    for dci in sorted(usr.discourse_coref_info, key=lambda x: x.index)
                    if dci.index == li.index
                ]
            )
            or "-",
            li.speakers_view if li.speakers_view else "-",
            # Scope (from sentence_type_info)
            usr.sentence_type_info[0].scope if usr.sentence_type_info else "-",
            # Construction info
            " ".join(
                [
                    f"{ci.cxn_index}:{ci.component_type}"
                    for ci in sorted(usr.construction_info, key=lambda x: x.index)
                    if ci.index == li.index
                ]
            )
            or "-",
        ]
        usr_lines.append("\t".join(line_parts))

    # Add sentence type markers if present
    if usr.sentence_type_info and usr.sentence_type_info[0].scope != "neutral":
        usr_lines.append(f"%{usr.sentence_type_info[0].scope}")

    # Close segment_id
    usr_lines.append("</segment_id>")

    usr_text = "\n".join(usr_lines)

    # Generate the visualization
    try:
        from graphviz import Digraph
        import tempfile
        import os

        def generate_visualization(usr_data):
            # Create a directed graph
            dot = Digraph(comment="USR Dependency Graph")
            dot.attr(rankdir="TB")  # Top to Bottom layout
            dot.attr("node", shape="box", style="rounded")

            # First parse all nodes and store their info
            nodes = {}
            hindi_words = {}
            construction_nodes = set()

            for line in usr_data.split("\n"):
                line = line.strip()
                if not line or line.startswith(("#", "<", "%", "//")):
                    if line.startswith("#"):  # Hindi words line
                        hindi_words = {
                            i + 1: word for i, word in enumerate(line[1:].split("\t"))
                        }
                    continue

                parts = line.split()
                if not parts:
                    continue

                node_id = parts[0]
                node_index = int(parts[1])

                # Check if this is a construction concept
                is_construction = node_id.startswith("[") and node_id.endswith("]")
                if is_construction:
                    construction_nodes.add(node_index)

                nodes[node_index] = {
                    "id": f"{node_id}_{node_index}",
                    "original_id": node_id,
                    "deps": [],
                    "word": hindi_words.get(node_index, node_id.split("_")[0]),
                    "is_construction": is_construction,
                }

                # Check column 5 (index 4) for dependencies
                if len(parts) > 4 and parts[4] != "-":
                    for dep_rel in parts[4].split():
                        if ":" in dep_rel:
                            head, rel = dep_rel.split(":")
                            if head.isdigit() or head == "0":
                                head_node = int(head) if head != "0" else "ROOT"
                                nodes[node_index]["deps"].append((head_node, rel))

                # Check column 9 (index 8) for construction relations
                if len(parts) > 8 and parts[8] != "-":
                    for const_rel in parts[8].split():
                        if ":" in const_rel:
                            head, rel = const_rel.split(":")
                            if head.isdigit():
                                nodes[node_index]["deps"].append((int(head), rel))

            # Add nodes to the graph
            for idx, node in nodes.items():
                if not node["is_construction"]:
                    dot.node(node["id"], label=f"{node['original_id']}\n{node['word']}")

            # Color palette for construction boxes
            construction_colors = ["#FFF2CC", "#D5E8D4", "#DAE8FC", "#E1D5E7"]

            # Create clusters for construction concepts
            for color_idx, constr_index in enumerate(construction_nodes):
                # Find all nodes related to this construction
                related_nodes = {constr_index}
                for idx, node in nodes.items():
                    for head_idx, _ in node["deps"]:
                        if head_idx == constr_index:
                            related_nodes.add(idx)

                # Get color
                box_color = construction_colors[color_idx % len(construction_colors)]

                # Create a subgraph for this construction
                with dot.subgraph(name=f"cluster_{constr_index}") as c:
                    c.attr(
                        style="filled,rounded,dotted",
                        color="gray50",
                        fillcolor=box_color,
                        label=nodes[constr_index]["original_id"],
                        fontcolor="black",
                        penwidth="2",
                    )
                    for node_idx in related_nodes:
                        node = nodes[node_idx]
                        c.node(
                            node["id"], label=f"{node['original_id']}\n{node['word']}"
                        )

            # Add edges based on dependencies
            for idx, node in nodes.items():
                for head_idx, rel in node["deps"]:
                    if head_idx == "ROOT":
                        continue
                    head_id = nodes[head_idx]["id"]
                    dot.edge(head_id, node["id"], label=rel)

            return dot

        # Generate the graph
        dot = generate_visualization(usr_text)

        # Create a temporary file
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
            temp_path = tmp.name

        # Render the graph
        dot.render(temp_path.replace(".png", ""), format="png", cleanup=True)

        # Read the image data
        with open(temp_path, "rb") as f:
            image_data = f.read()

        # Clean up
        os.unlink(temp_path)

        # Return the image
        from flask import make_response

        response = make_response(image_data)
        response.headers.set("Content-Type", "image/png")
        response.headers.set(
            "Content-Disposition", "inline", filename=f"usr_{segment_id}.png"
        )
        return response

    except Exception as e:
        return jsonify({"msg": "Error generating visualization", "error": str(e)}), 500


def parse_custom_usr_format(raw_data):
    """Parse the custom USR format with 9 columns, ensuring all concepts appear in all tables."""
    parsed_data = {
        "sentence_type": "declarative",  # default sentence type
        "lexical_info": [],
        "dependency_info": [],
        "discourse_coref_info": [],
        "construction_info": [],
        "sentence_type_info": {
            "sentence_type": "declarative",  # will be set by % marker
            "scope": None,  # scope is per-concept, not global
        },
    }

    lines = raw_data.split("\n")
    segment_id = None

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Handle metadata
        if line.startswith("<segment_id="):
            segment_id = line[12:-1].strip()
            continue
        elif line.startswith("</segment_id>") or line.startswith("#"):
            continue
        elif line.startswith("%"):
            # This sets the overall sentence type
            marker = line[1:].lower().strip()
            if marker in ["affirmative", "negative", "interrogative"]:
                parsed_data["sentence_type"] = marker
                parsed_data["sentence_type_info"]["sentence_type"] = marker
            continue

        # Process token lines (9 columns)
        columns = line.split("\t")
        if len(columns) < 9:
            continue

        # Get the full concept name from the first column (don't split it)
        concept_full = columns[0].strip()

        # Handle index (required field)
        try:
            index = (
                int(columns[1].strip())
                if columns[1].strip() and columns[1].strip() != "-"
                else 0
            )
        except ValueError:
            index = 0

        # --- LEXICAL INFO ---
        lexical_item = {
            "concept": concept_full,
            "index": index,
            "semantic_category": (
                columns[2].strip() if columns[2].strip() != "-" else None
            ),
            "morpho_semantic": (
                columns[3].strip() if columns[3].strip() != "-" else None
            ),
            "speakers_view": columns[6].strip() if columns[6].strip() != "-" else None,
            "scope": (
                columns[7].strip() if columns[7].strip() != "-" else None
            ),  # Scope from column 7
        }
        parsed_data["lexical_info"].append(lexical_item)

        # --- DEPENDENCY INFO ---
        dep_relations = []
        if columns[4].strip() != "-":
            for dep_rel in columns[4].strip().split():
                if ":" in dep_rel:
                    head, relation = dep_rel.split(":", 1)
                    try:
                        head_index = int(head) if head and head != "-" else None
                        dep_relations.append((head_index, relation))
                    except ValueError:
                        continue

        # If no relations, add a default entry
        if not dep_relations:
            dep_relations.append((None, "-"))

        for head_index, relation in dep_relations:
            parsed_data["dependency_info"].append(
                {
                    "concept": concept_full,
                    "index": index,
                    "head_index": head_index,
                    "relation": relation,
                }
            )

        # --- DISCOURSE/COREF INFO ---
        coref_relations = []
        if columns[5].strip() != "-":
            for coref_rel in columns[5].strip().split():
                if ":" in coref_rel:
                    head, relation = coref_rel.split(":", 1)
                    try:
                        head_index = int(head) if head and head != "-" else None
                        coref_relations.append((head_index, relation))
                    except ValueError:
                        continue

        # If no relations, add a default entry
        if not coref_relations:
            coref_relations.append((None, "-"))

        for head_index, relation in coref_relations:
            parsed_data["discourse_coref_info"].append(
                {
                    "concept": concept_full,
                    "index": index,
                    "head_index": head_index,
                    "relation": relation,
                }
            )

        # --- CONSTRUCTION INFO ---
        const_relations = []
        if columns[8].strip() != "-":
            for const_rel in columns[8].strip().split():
                if ":" in const_rel:
                    cxn_index, component = const_rel.split(":", 1)
                    try:
                        cxn_index = (
                            int(cxn_index) if cxn_index and cxn_index != "-" else None
                        )
                        const_relations.append((cxn_index, component))
                    except ValueError:
                        continue

        # If no relations, add a default entry
        if not const_relations:
            const_relations.append((None, "-"))

        for cxn_index, component in const_relations:
            parsed_data["construction_info"].append(
                {
                    "concept": concept_full,
                    "index": index,
                    "cxn_index": cxn_index,
                    "component_type": component,
                }
            )

    return parsed_data


@admin_bp.route("/usr/<int:segment_id>", methods=["POST"])
@jwt_required()
def create_usr(segment_id):
    if not admin_only():
        return jsonify({"msg": "Admin privileges required"}), 403

    data = request.json

    # Check if this is a custom format request
    if "raw_format" in data and data["raw_format"]:
        try:
            data = parse_custom_usr_format(data["raw_text"])
        except Exception as e:
            return jsonify({"msg": f"Error parsing custom format: {str(e)}"}), 400

    # Create USR first
    usr = USR(
        segment_id=segment_id,
        sentence_type=data.get("sentence_type", "declarative"),
        status="Pending",
    )
    db.session.add(usr)
    db.session.flush()  # Get the USR ID

    # Add Lexical Info (always exists for each concept)
    for lex_item in data.get("lexical_info", []):
        lex = LexicalInfo(
            usr_id=usr.id,
            concept=lex_item["concept"],
            index=lex_item["index"],
            semantic_category=lex_item.get("semantic_category"),
            morpho_semantic=lex_item.get("morpho_semantic"),
            speakers_view=lex_item.get("speakers_view"),
        )
        db.session.add(lex)

    # Add Dependency Info (always exists for each concept)
    for dep_item in data.get("dependency_info", []):
        dep = DependencyInfo(
            usr_id=usr.id,
            concept=dep_item["concept"],
            index=dep_item["index"],
            head_index=(
                str(dep_item["head_index"])
                if dep_item["head_index"] is not None
                else None
            ),
            relation=dep_item["relation"],
        )
        db.session.add(dep)

    # Add Discourse/Coref Info (always exists for each concept)
    for disc_item in data.get("discourse_coref_info", []):
        disc = DiscourseCorefInfo(
            usr_id=usr.id,
            concept=disc_item["concept"],
            index=disc_item["index"],
            head_index=(
                str(disc_item["head_index"])
                if disc_item["head_index"] is not None
                else None
            ),
            relation=disc_item["relation"],
        )
        db.session.add(disc)

    # Add Construction Info (always exists for each concept)
    for const_item in data.get("construction_info", []):
        const = ConstructionInfo(
            usr_id=usr.id,
            concept=const_item["concept"],
            index=const_item["index"],
            cxn_index=(
                str(const_item["cxn_index"])
                if const_item["cxn_index"] is not None
                else None
            ),
            component_type=const_item["component_type"],
        )
        db.session.add(const)

    # Add Sentence Type Info
    stype = SentenceTypeInfo(
        usr_id=usr.id,
        sentence_type=data.get("sentence_type", "declarative"),
        scope=data.get("sentence_type_info", {}).get("scope"),
    )
    db.session.add(stype)

    try:
        db.session.commit()
        return jsonify(
            {
                "msg": "USR created with all components",
                "usr_id": usr.id,
                "lexical_count": len(data.get("lexical_info", [])),
                "dependency_count": len(data.get("dependency_info", [])),
                "discourse_count": len(data.get("discourse_coref_info", [])),
                "construction_count": len(data.get("construction_info", [])),
            }
        )
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error creating USR: {str(e)}")
        return jsonify({"msg": "Error creating USR", "error": str(e)}), 500


@admin_bp.route("/usr/<int:usr_id>", methods=["GET"])
@jwt_required()
def get_usr(usr_id):
    if not admin_only():
        return jsonify({"msg": "Admin privileges required"}), 403

    usr = USR.query.get(usr_id)
    if not usr:
        return jsonify({"msg": "USR not found"}), 404

    # Get all related data
    lexical_info = [
        {
            "concept": li.concept,
            "index": li.index,
            "semantic_category": li.semantic_category,
            "morpho_semantic": li.morpho_semantic,
            "speakers_view": li.speakers_view,
        }
        for li in usr.lexical_info
    ]

    dependency_info = [
        {
            "concept": di.concept,
            "index": di.index,
            "head_index": di.head_index,
            "relation": di.relation,
        }
        for di in usr.dependency_info
    ]

    discourse_coref_info = [
        {
            "concept": dci.concept,
            "index": dci.index,
            "head_index": dci.head_index,
            "relation": dci.relation,
        }
        for dci in usr.discourse_coref_info
    ]

    construction_info = [
        {
            "concept": ci.concept,
            "index": ci.index,
            "cxn_index": ci.cxn_index,
            "component_type": ci.component_type,
        }
        for ci in usr.construction_info
    ]

    sentence_type_info = {}
    if usr.sentence_type_info:
        sti = usr.sentence_type_info[0]  # Assuming one-to-one
        sentence_type_info = {"sentence_type": sti.sentence_type, "scope": sti.scope}

    return jsonify(
        {
            "usr_id": usr.id,
            "segment_id": usr.segment_id,
            "sentence_type": usr.sentence_type,
            "lexical_info": lexical_info,
            "dependency_info": dependency_info,
            "discourse_coref_info": discourse_coref_info,
            "construction_info": construction_info,
            "sentence_type_info": sentence_type_info,
        }
    )


@admin_bp.route("/usr/<int:usr_id>", methods=["DELETE"])
@jwt_required()
def delete_usr(usr_id):
    if not admin_only():
        return jsonify({"msg": "Admin privileges required"}), 403

    usr = USR.query.get(usr_id)
    if not usr:
        return jsonify({"msg": "USR not found"}), 404

    try:
        # Will cascade to all info tables and assignments
        db.session.delete(usr)
        db.session.commit()
        return jsonify({"msg": "USR deleted successfully"})
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error deleting USR: {str(e)}")
        return jsonify({"msg": "Error deleting USR", "error": str(e)}), 500


# ASSIGNMENT ROUTES
@admin_bp.route("/assign_usr", methods=["POST"])
@jwt_required()
def assign_usr():
    if not admin_only():
        return jsonify({"msg": "Admin privileges required"}), 403

    data = request.json
    usr_id = data.get("usr_id")
    annotator_id = data.get("annotator_id")
    reviewer_id = data.get("reviewer_id")

    # Check if USR exists
    usr = USR.query.get(usr_id)
    if not usr:
        return jsonify({"msg": "USR not found"}), 404

    # Check if users exist and have correct roles
    annotator = User.query.get(annotator_id)
    if not annotator or annotator.role != "annotator":
        return jsonify({"msg": "Invalid annotator"}), 400

    if reviewer_id:
        reviewer = User.query.get(reviewer_id)
        if not reviewer or reviewer.role != "reviewer":
            return jsonify({"msg": "Invalid reviewer"}), 400

    # Create assignment for the USR
    assignment = Assignment(
        usr_id=usr_id,
        segment_id=usr.segment_id,
        annotator_id=annotator_id,
        reviewer_id=reviewer_id,
        annotation_status="Assigned",
        assign_lexical=data.get("can_edit_lexical", False)
        or data.get("assign_lexical", False),
        assign_dependency=data.get("can_edit_dependency", False)
        or data.get("assign_dependency", False),
        assign_discourse=data.get("can_edit_discourse", False)
        or data.get("assign_discourse", False),
        assign_construction=data.get("can_edit_construction", False)
        or data.get("assign_construction", False),
    )
    db.session.add(assignment)

    try:
        db.session.commit()
        return jsonify({"msg": "USR assigned successfully"})
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error assigning USR: {str(e)}")
        return jsonify({"msg": "Error assigning USR", "error": str(e)}), 500


@admin_bp.route("/usr_assignments/<int:usr_id>", methods=["GET"])
@jwt_required()
def get_usr_assignments(usr_id):
    if not admin_only():
        return jsonify({"msg": "Admin privileges required"}), 403

    assignments = Assignment.query.filter_by(usr_id=usr_id).all()
    return jsonify(
        [
            {
                "id": a.id,
                "usr_id": a.usr_id,
                "segment_id": a.segment_id,
                "annotator_id": a.annotator_id,
                "reviewer_id": a.reviewer_id,
                "annotation_status": a.annotation_status,
                "assign_lexical": a.assign_lexical,
                "assign_dependency": a.assign_dependency,
                "assign_discourse": a.assign_discourse,
                "assign_construction": a.assign_construction,
            }
            for a in assignments
        ]
    )


@admin_bp.route("/segment_assignments/<int:segment_id>", methods=["GET"])
@jwt_required()
def get_segment_assignments(segment_id):
    if not admin_only():
        return jsonify({"msg": "Admin privileges required"}), 403

    assignments = Assignment.query.filter_by(segment_id=segment_id).all()
    return jsonify(
        [
            {
                "id": a.id,
                "segment_id": a.segment_id,
                "usr_id": a.usr_id,
                "annotator_id": a.annotator_id,
                "reviewer_id": a.reviewer_id,
                "annotation_status": a.annotation_status,
                "assign_lexical": a.assign_lexical,
                "assign_dependency": a.assign_dependency,
                "assign_discourse": a.assign_discourse,
                "assign_construction": a.assign_construction,
            }
            for a in assignments
        ]
    )


@admin_bp.route("/assignments", methods=["GET"])
@jwt_required()
def get_all_assignments():
    if not admin_only():
        return jsonify({"msg": "Admin privileges required"}), 403

    # Query all assignments with related data
    assignments = (
        db.session.query(
            Assignment,
            User.name.label("annotator_name"),
            User.email.label("annotator_email"),
            Segment.segment_id,
            Sentence.sentence_id,
            Chapter.title.label("chapter_title"),
            Project.title.label("project_title"),
        )
        .join(User, Assignment.annotator_id == User.id)
        .join(Segment, Assignment.segment_id == Segment.id)
        .join(Sentence, Segment.sentence_id == Sentence.id)
        .join(Chapter, Sentence.chapter_id == Chapter.id)
        .join(Project, Chapter.project_id == Project.id)
        .all()
    )

    # Group assignments by user
    assignments_by_user = {}
    for a in assignments:
        user_key = f"{a.annotator_name} ({a.annotator_email})"
        if user_key not in assignments_by_user:
            assignments_by_user[user_key] = {
                "annotator_id": a.Assignment.annotator_id,
                "annotator_name": a.annotator_name,
                "annotator_email": a.annotator_email,
                "assignments": [],
            }

        assignments_by_user[user_key]["assignments"].append(
            {
                "id": a.Assignment.id,
                "usr_id": a.Assignment.usr_id,
                "segment_id": a.Assignment.segment_id,
                "segment_identifier": a.segment_id,
                "sentence_identifier": a.sentence_id,
                "chapter_title": a.chapter_title,
                "project_title": a.project_title,
                "reviewer_id": a.Assignment.reviewer_id,
                "annotation_status": a.Assignment.annotation_status,
                "assign_lexical": a.Assignment.assign_lexical,
                "assign_dependency": a.Assignment.assign_dependency,
                "assign_discourse": a.Assignment.assign_discourse,
                "assign_construction": a.Assignment.assign_construction,
                "created_at": (
                    a.Assignment.created_at.isoformat()
                    if a.Assignment.created_at
                    else None
                ),
                "updated_at": (
                    a.Assignment.updated_at.isoformat()
                    if a.Assignment.updated_at
                    else None
                ),
            }
        )

    # Convert to list format for response
    result = [
        {"annotator": key, "details": value}
        for key, value in assignments_by_user.items()
    ]

    return jsonify(result)


@admin_bp.route("/assignment/<int:assignment_id>", methods=["PUT"])
@jwt_required()
def update_assignment(assignment_id):
    if not admin_only():
        return jsonify({"msg": "Admin privileges required"}), 403

    assignment = Assignment.query.get(assignment_id)
    if not assignment:
        return jsonify({"msg": "Assignment not found"}), 404

    data = request.json
    try:
        if "annotator_id" in data:
            assignment.annotator_id = data["annotator_id"]
        if "reviewer_id" in data:
            assignment.reviewer_id = data["reviewer_id"]
        if "annotation_status" in data:
            assignment.annotation_status = data["annotation_status"]
        if "assign_lexical" in data:
            assignment.assign_lexical = data["assign_lexical"]
        if "assign_dependency" in data:
            assignment.assign_dependency = data["assign_dependency"]
        if "assign_discourse" in data:
            assignment.assign_discourse = data["assign_discourse"]
        if "assign_construction" in data:
            assignment.assign_construction = data["assign_construction"]

        db.session.commit()
        return jsonify({"msg": "Assignment updated"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": "Error updating assignment", "error": str(e)}), 500


@admin_bp.route("/assignment/<int:assignment_id>", methods=["DELETE"])
@jwt_required()
def delete_assignment(assignment_id):
    if not admin_only():
        return jsonify({"msg": "Admin privileges required"}), 403

    assignment = Assignment.query.get(assignment_id)
    if not assignment:
        return jsonify({"msg": "Assignment not found"}), 404

    try:
        db.session.delete(assignment)
        db.session.commit()
        return jsonify({"msg": "Assignment deleted"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": "Error deleting assignment", "error": str(e)}), 500


# GET FULL HIERARCHY
@admin_bp.route("/project/<int:project_id>/hierarchy", methods=["GET"])
@jwt_required()
def get_project_hierarchy(project_id):
    if not admin_only():
        return jsonify({"msg": "Admin privileges required"}), 403

    project = Project.query.get(project_id)
    if not project:
        return jsonify({"msg": "Project not found"}), 404

    chapters = []
    for chapter in project.chapters:
        sentences = []
        for sentence in chapter.sentences:
            segments = []
            for segment in sentence.segments:
                usrs = []
                for usr in segment.usrs:
                    # Build the custom USR format string
                    usr_lines = []

                    # Add sent_id header
                    usr_lines.append(f"<sent_id={segment.segment_id or usr.id}>")

                    # Add sentence text (commented)
                    usr_lines.append(f"#{segment.text}")

                    # Add lexical info lines
                    for li in usr.lexical_info:
                        line_parts = [
                            li.concept,
                            str(li.index),
                            li.semantic_category if li.semantic_category else "-",
                            li.morpho_semantic if li.morpho_semantic else "-",
                            # Dependency info
                            " ".join(
                                [
                                    f"{di.head_index}:{di.relation}"
                                    for di in usr.dependency_info
                                    if di.index == li.index
                                ]
                            )
                            or "-",
                            # Discourse/Coref info
                            " ".join(
                                [
                                    f"{dci.head_index}:{dci.relation}"
                                    for dci in usr.discourse_coref_info
                                    if dci.index == li.index
                                ]
                            )
                            or "-",
                            li.speakers_view if li.speakers_view else "-",
                            # Scope (from sentence_type_info)
                            (
                                usr.sentence_type_info[0].scope
                                if usr.sentence_type_info
                                else "-"
                            ),
                            # Construction info
                            " ".join(
                                [
                                    f"{ci.cxn_index}:{ci.component_type}"
                                    for ci in usr.construction_info
                                    if ci.index == li.index
                                ]
                            )
                            or "-",
                        ]
                        usr_lines.append("\t".join(line_parts))

                    # Add sentence type markers if present
                    if (
                        usr.sentence_type_info
                        and usr.sentence_type_info[0].scope != "neutral"
                    ):
                        usr_lines.append(f"%{usr.sentence_type_info[0].scope}")

                    # Close sent_id
                    usr_lines.append("</sent_id>")

                    # Join all lines with newlines
                    usr_text = "\n".join(usr_lines)

                    usrs.append(
                        {
                            "id": usr.id,
                            "status": usr.status,
                            "sentence_type": usr.sentence_type,
                            "raw_text": usr_text,
                            "lexical_info": [
                                {
                                    "concept": li.concept,
                                    "index": li.index,
                                    "semantic_category": li.semantic_category,
                                    "morpho_semantic": li.morpho_semantic,
                                    "speakers_view": li.speakers_view,
                                }
                                for li in usr.lexical_info
                            ],
                            "dependency_info": [
                                {
                                    "concept": di.concept,
                                    "index": di.index,
                                    "head_index": di.head_index,
                                    "relation": di.relation,
                                }
                                for di in usr.dependency_info
                            ],
                            "discourse_coref_info": [
                                {
                                    "concept": dci.concept,
                                    "index": dci.index,
                                    "head_index": dci.head_index,
                                    "relation": dci.relation,
                                }
                                for dci in usr.discourse_coref_info
                            ],
                            "construction_info": [
                                {
                                    "concept": ci.concept,
                                    "index": ci.index,
                                    "cxn_index": ci.cxn_index,
                                    "component_type": ci.component_type,
                                }
                                for ci in usr.construction_info
                            ],
                            "sentence_type_info": {
                                "sentence_type": usr.sentence_type,
                                "scope": (
                                    usr.sentence_type_info[0].scope
                                    if usr.sentence_type_info
                                    else "neutral"
                                ),
                            },
                        }
                    )

                segments.append(
                    {
                        "id": segment.id,
                        "text": segment.text,
                        "wxtext": segment.wxtext,
                        "englishtext": segment.englishtext,
                        "segment_id": segment.segment_id,
                        "usrs": usrs,
                    }
                )

            sentences.append(
                {
                    "id": sentence.id,
                    "text": sentence.text,
                    "sentence_id": sentence.sentence_id,
                    "segments": segments,
                }
            )

        chapters.append(
            {"id": chapter.id, "title": chapter.title, "sentences": sentences}
        )

    return jsonify(
        {
            "project": {
                "id": project.id,
                "title": project.title,
                "description": project.description,
                "chapters": chapters,
            }
        }
    )
