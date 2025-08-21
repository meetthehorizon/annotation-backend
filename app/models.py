from . import db
from werkzeug.security import generate_password_hash, check_password_hash


class User(db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(
        db.String(50), nullable=False, default="pending"
    )  # admin, annotator, reviewer
    organization = db.Column(db.String(150))
    status = db.Column(db.String(50), default="pending")
    otp = db.Column(db.String(6), nullable=True)
    otp_expiration = db.Column(db.DateTime, nullable=True)

    annotator_assignments = db.relationship(
        "Assignment",
        foreign_keys="Assignment.annotator_id",
        back_populates="annotator",
        lazy=True,
        cascade="all, delete-orphan",
    )
    reviewer_assignments = db.relationship(
        "Assignment",
        foreign_keys="Assignment.reviewer_id",
        back_populates="reviewer",
        lazy=True,
        cascade="all, delete-orphan",
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Project(db.Model):
    __tablename__ = "project"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    language = db.Column(
        db.String(50), nullable=False, default="hindi"
    )  # Add this line

    chapters = db.relationship(
        "Chapter", back_populates="project", lazy=True, cascade="all, delete-orphan"
    )


class Chapter(db.Model):
    __tablename__ = "chapter"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("project.id"), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    language = db.Column(
        db.String(50), nullable=False, default="hindi"
    )  # Add this line

    project = db.relationship("Project", back_populates="chapters")
    sentences = db.relationship(
        "Sentence", back_populates="chapter", lazy=True, cascade="all, delete-orphan"
    )


class Sentence(db.Model):
    __tablename__ = "sentence"

    id = db.Column(db.Integer, primary_key=True)
    chapter_id = db.Column(db.Integer, db.ForeignKey("chapter.id"), nullable=False)
    text = db.Column(db.Text, nullable=False)
    sentence_id = db.Column(db.String(100))  # e.g., Geo_nios_3ch_0002
    language = db.Column(
        db.String(50), nullable=False, default="hindi"
    )  # Add this line

    chapter = db.relationship("Chapter", back_populates="sentences")
    segments = db.relationship(
        "Segment", back_populates="sentence", lazy=True, cascade="all, delete-orphan"
    )


class Segment(db.Model):
    __tablename__ = "segment"

    id = db.Column(db.Integer, primary_key=True)
    sentence_id = db.Column(db.Integer, db.ForeignKey("sentence.id"), nullable=False)
    text = db.Column(db.Text, nullable=False)
    wxtext = db.Column(db.Text)
    englishtext = db.Column(db.Text)
    segment_id = db.Column(db.String(100))  # e.g., Geo_nios_3ch_0002
    language = db.Column(
        db.String(50), nullable=False, default="hindi"
    )  # Add this line

    sentence = db.relationship("Sentence", back_populates="segments")
    usrs = db.relationship(
        "USR", back_populates="segment", lazy=True, cascade="all, delete-orphan"
    )
    assignments = db.relationship(
        "Assignment", back_populates="segment", lazy=True, cascade="all, delete-orphan"
    )


class USR(db.Model):
    __tablename__ = "usr"

    id = db.Column(db.Integer, primary_key=True)
    segment_id = db.Column(db.Integer, db.ForeignKey("segment.id"), nullable=False)
    status = db.Column(db.String(50), default="Pending")
    sentence_type = db.Column(db.String(100))  # e.g., %affirmative
    language = db.Column(db.String(50), nullable=False, default="hindi")
    # Relationships
    segment = db.relationship("Segment", back_populates="usrs")
    lexical_info = db.relationship(
        "LexicalInfo", back_populates="usr", lazy=True, cascade="all, delete-orphan"
    )
    dependency_info = db.relationship(
        "DependencyInfo", back_populates="usr", lazy=True, cascade="all, delete-orphan"
    )
    discourse_coref_info = db.relationship(
        "DiscourseCorefInfo",
        back_populates="usr",
        lazy=True,
        cascade="all, delete-orphan",
    )
    construction_info = db.relationship(
        "ConstructionInfo",
        back_populates="usr",
        lazy=True,
        cascade="all, delete-orphan",
    )
    sentence_type_info = db.relationship(
        "SentenceTypeInfo",
        back_populates="usr",
        lazy=True,
        cascade="all, delete-orphan",
    )
    assignments = db.relationship(
        "Assignment", back_populates="usr", lazy=True, cascade="all, delete-orphan"
    )


class LexicalInfo(db.Model):
    __tablename__ = "lexical_info"

    id = db.Column(db.Integer, primary_key=True)
    usr_id = db.Column(db.Integer, db.ForeignKey("usr.id"), nullable=False)
    concept = db.Column(db.String(100), nullable=False)
    index = db.Column(db.Integer, nullable=False)
    semantic_category = db.Column(db.String(100))
    morpho_semantic = db.Column(db.String(100))
    speakers_view = db.Column(db.String(100))

    # Relationships
    usr = db.relationship("USR", back_populates="lexical_info")


class DependencyInfo(db.Model):
    __tablename__ = "dependency_info"

    id = db.Column(db.Integer, primary_key=True)
    usr_id = db.Column(db.Integer, db.ForeignKey("usr.id"), nullable=False)
    concept = db.Column(db.String(100), nullable=False)
    index = db.Column(db.Integer, nullable=False)
    head_index = db.Column(db.String(20))  # Changed from Integer
    relation = db.Column(db.String(100), nullable=False)

    # Relationships
    usr = db.relationship("USR", back_populates="dependency_info")


class DiscourseCorefInfo(db.Model):
    __tablename__ = "discourse_coref_info"

    id = db.Column(db.Integer, primary_key=True)
    usr_id = db.Column(db.Integer, db.ForeignKey("usr.id"), nullable=False)
    concept = db.Column(db.String(100), nullable=False)
    index = db.Column(db.Integer, nullable=False)
    head_index = db.Column(db.String(20))  # Changed from Integer
    relation = db.Column(db.String(100), nullable=False)

    # Relationships
    usr = db.relationship("USR", back_populates="discourse_coref_info")


class ConstructionInfo(db.Model):
    __tablename__ = "construction_info"

    id = db.Column(db.Integer, primary_key=True)
    usr_id = db.Column(db.Integer, db.ForeignKey("usr.id"), nullable=False)
    concept = db.Column(db.String(100), nullable=False)
    index = db.Column(db.Integer, nullable=False)
    cxn_index = db.Column(db.String(20))  # Changed from Integer
    component_type = db.Column(db.String(100), nullable=False)

    # Relationships
    usr = db.relationship("USR", back_populates="construction_info")


class SentenceTypeInfo(db.Model):
    __tablename__ = "sentence_type_info"

    id = db.Column(db.Integer, primary_key=True)
    usr_id = db.Column(db.Integer, db.ForeignKey("usr.id"), nullable=False)
    sentence_type = db.Column(db.String(100), nullable=False)
    scope = db.Column(db.String(100))

    # Relationships
    usr = db.relationship("USR", back_populates="sentence_type_info")


class Assignment(db.Model):
    __tablename__ = "assignment"

    id = db.Column(db.Integer, primary_key=True)
    usr_id = db.Column(db.Integer, db.ForeignKey("usr.id"))
    segment_id = db.Column(db.Integer, db.ForeignKey("segment.id"))
    annotator_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    reviewer_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    annotation_status = db.Column(db.String(50), default="Unassigned")
    assign_lexical = db.Column(db.Boolean, default=False)
    assign_construction = db.Column(db.Boolean, default=False)
    assign_dependency = db.Column(db.Boolean, default=False)
    assign_discourse = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(
        db.DateTime,
        default=db.func.current_timestamp(),
        onupdate=db.func.current_timestamp(),
    )
    # Relationships
    usr = db.relationship("USR", back_populates="assignments")
    segment = db.relationship("Segment", back_populates="assignments")
    annotator = db.relationship(
        "User", foreign_keys=[annotator_id], back_populates="annotator_assignments"
    )
    reviewer = db.relationship(
        "User", foreign_keys=[reviewer_id], back_populates="reviewer_assignments"
    )


class Concept(db.Model):
    __tablename__ = "concept"

    id = db.Column(db.Integer, primary_key=True)
    concept_label = db.Column(db.String(200), nullable=False, unique=True)
    hindi_label = db.Column(db.String(200))
    sanskrit_label = db.Column(db.String(200))
    english_label = db.Column(db.String(200))
    mrsc = db.Column(db.String(200))
